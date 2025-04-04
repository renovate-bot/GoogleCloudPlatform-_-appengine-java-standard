/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.apphosting.runtime;

import static com.google.apphosting.runtime.AppEngineConstants.GAE_RUNTIME;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import com.google.appengine.api.ThreadManager;
import com.google.apphosting.api.ApiProxy;
import com.google.apphosting.base.protos.HttpPb.ParsedHttpHeader;
import com.google.apphosting.base.protos.RuntimePb.UPRequest;
import com.google.apphosting.base.protos.RuntimePb.UPResponse;
import com.google.apphosting.runtime.anyrpc.AnyRpcServerContext;
import com.google.auto.value.AutoBuilder;
import com.google.common.base.Ascii;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Exchanger;
import java.util.concurrent.TimeoutException;

/**
 * Runs an inbound request within the context of the given app, whether ordinary inbound HTTP or
 * background request.
 */
public class RequestRunner implements Runnable {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /**
   * How long should we wait for {@code ApiProxyImpl} to exchange the background thread's {@code
   * Runnable}.
   */
  public static final Duration WAIT_FOR_USER_RUNNABLE_DEADLINE = Duration.ofSeconds(60);

  private final UPRequestHandler upRequestHandler;
  private final RequestManager requestManager;
  private final BackgroundRequestCoordinator coordinator;
  private final boolean compressResponse;
  private final AppVersion appVersion;
  private final AnyRpcServerContext rpc;
  private final UPRequest upRequest;
  private final MutableUpResponse upResponse;

  /** Get a partly-initialized builder. */
  public static Builder builder() {
    return new AutoBuilder_RequestRunner_Builder();
  }

  /** Builder for RequestRunner. */
  @AutoBuilder
  public abstract static class Builder {
    Builder() {}

    public abstract Builder setUpRequestHandler(UPRequestHandler upRequestHandler);

    public abstract Builder setRequestManager(RequestManager requestManager);

    public abstract Builder setCoordinator(BackgroundRequestCoordinator coordinator);

    public abstract Builder setCompressResponse(boolean compressResponse);

    public abstract Builder setAppVersion(AppVersion appVersion);

    public abstract Builder setRpc(AnyRpcServerContext rpc);

    public abstract Builder setUpRequest(UPRequest upRequest);

    public abstract Builder setUpResponse(MutableUpResponse upResponse);

    public abstract RequestRunner build();
  }

  public RequestRunner(
      UPRequestHandler upRequestHandler,
      RequestManager requestManager,
      BackgroundRequestCoordinator coordinator,
      boolean compressResponse,
      AppVersion appVersion,
      AnyRpcServerContext rpc,
      UPRequest upRequest,
      MutableUpResponse upResponse) {
    this.upRequestHandler = upRequestHandler;
    this.requestManager = requestManager;
    this.coordinator = coordinator;
    this.compressResponse = compressResponse;
    this.appVersion = appVersion;
    this.rpc = rpc;
    this.upRequest = upRequest;
    this.upResponse = upResponse;
  }

  /** Create a failure response from the given code and message. */
  public static void setFailure(
      MutableUpResponse response, UPResponse.ERROR error, String message) {
    logger.atWarning().log("Runtime failed: %s, %s", error, message);
    // If the response is already set, use that -- it's probably more
    // specific (e.g. THREADS_STILL_RUNNING).
    if (response.getError() == UPResponse.ERROR.OK_VALUE) {
      response.setError(error.getNumber());
      response.setErrorMessage(message);
    }
  }

  private String formatLogLine(String message, Throwable ex) {
    StringWriter stringWriter = new StringWriter();
    PrintWriter printWriter = new PrintWriter(stringWriter);
    printWriter.println(message);
    ex.printStackTrace(printWriter);
    return stringWriter.toString();
  }

  public static boolean shouldKillCloneAfterException(Throwable th) {
    while (th != null) {
      if (th instanceof OutOfMemoryError) {
        return true;
      }
      try {
        Throwable[] suppressed = th.getSuppressed();
        if (suppressed != null) {
          for (Throwable s : suppressed) {
            if (shouldKillCloneAfterException(s)) {
              return true;
            }
          }
        }
      } catch (OutOfMemoryError ex) {
        return true;
      }
      // TODO: Consider checking for other subclasses of
      // VirtualMachineError, but probably not StackOverflowError.
      th = th.getCause();
    }
    return false;
  }

  private String getBackgroundRequestId(UPRequest upRequest) {
    for (ParsedHttpHeader header : upRequest.getRequest().getHeadersList()) {
      if (Ascii.equalsIgnoreCase(
          header.getKey(), AppEngineConstants.X_APPENGINE_BACKGROUNDREQUEST)) {
        return header.getValue();
      }
    }
    throw new IllegalArgumentException("Did not receive a background request identifier.");
  }

  /** Creates a thread which does nothing except wait on the thread that spawned it. */
  private static class ThreadProxy extends Thread {

    private final Thread proxy;

    private ThreadProxy() {
      super(
          Thread.currentThread().getThreadGroup().getParent(),
          Thread.currentThread().getName() + "-proxy");
      proxy = Thread.currentThread();
    }

    @Override
    public synchronized void start() {
      proxy.start();
      super.start();
    }

    @Override
    public void setUncaughtExceptionHandler(UncaughtExceptionHandler eh) {
      proxy.setUncaughtExceptionHandler(eh);
    }

    @Override
    public void run() {
      Uninterruptibles.joinUninterruptibly(proxy);
    }
  }

  @Override
  public void run() {
    ThreadGroup currentThreadGroup = Thread.currentThread().getThreadGroup();
    RequestManager.RequestToken requestToken =
        requestManager.startRequest(appVersion, rpc, upRequest, upResponse, currentThreadGroup);
    try {
      dispatchRequest(requestToken);
    } catch (
        @SuppressWarnings("InterruptedExceptionSwallowed")
        Throwable ex) {
      // Note we do intentionally swallow InterruptException.
      // We will report the exception via the rpc. We don't mark this thread as interrupted because
      // ThreadGroupPool would use that as a signal to remove the thread from the pool; we don't
      // need that.
      handleException(ex, requestToken);
    } finally {
      requestManager.finishRequest(requestToken);
    }
    // Do not put this in a finally block.  If we propagate an
    // exception the callback will be invoked automatically.
    rpc.finishWithResponse(upResponse.build());
    // We don't want threads used for background requests to go back
    // in the thread pool, because users may have stashed references
    // to them or may be expecting them to exit.  Setting the
    // interrupt bit causes the pool to drop them.
    if (upRequest.getRequestType() == UPRequest.RequestType.BACKGROUND) {
      Thread.currentThread().interrupt();
    }
  }

  private void dispatchRequest(RequestManager.RequestToken requestToken) throws Exception {
    switch (upRequest.getRequestType()) {
      case SHUTDOWN:
        logger.atInfo().log("Shutting down requests");
        requestManager.shutdownRequests(requestToken);
        break;
      case BACKGROUND:
        dispatchBackgroundRequest();
        break;
      case OTHER:
        dispatchServletRequest();
        break;
    }
  }

  private void dispatchBackgroundRequest() throws InterruptedException, TimeoutException {
    String requestId = getBackgroundRequestId(upRequest);
    // For java21 runtime, RPC path, do the new background thread handling for now, and keep it for
    // other runtimes.
    if (!Objects.equals(GAE_RUNTIME, "java21")) {
      // Wait here for synchronization with the ThreadFactory.
      CountDownLatch latch = ThreadGroupPool.resetCurrentThread();
      Thread thread = new ThreadProxy();
      Runnable runnable =
          coordinator.waitForUserRunnable(
              requestId, thread, WAIT_FOR_USER_RUNNABLE_DEADLINE.toMillis());
      // Wait here until someone calls start() on the thread again.
      latch.await();
      // Now set the context class loader to the UserClassLoader for the application
      // and pass control to the Runnable the user provided.
      ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
      Thread.currentThread().setContextClassLoader(appVersion.getClassLoader());
      try {
        runnable.run();
      } finally {
        Thread.currentThread().setContextClassLoader(oldClassLoader);
      }
    } else {
      // The interface of coordinator.waitForUserRunnable() requires us to provide the app code with
      // a
      // working thread *in the same exchange* where we get the runnable the user wants to run in
      // the
      // thread. This prevents us from actually directly feeding that runnable to the thread. To
      // work
      // around this conundrum, we create an EagerRunner, which lets us start running the thread
      // without knowing yet what we want to run.

      // Create an ordinary request thread as a child of this background thread.
      EagerRunner eagerRunner = new EagerRunner();
      Thread thread = ThreadManager.createThreadForCurrentRequest(eagerRunner);

      // Give this thread to the app code and get its desired runnable in response:
      Runnable runnable =
          coordinator.waitForUserRunnable(
              requestId, thread, WAIT_FOR_USER_RUNNABLE_DEADLINE.toMillis());

      // Finally, hand that runnable to the thread so it can actually start working.
      // This will block until Thread.start() is called by the app code. This is by design: we must
      // not exit this request handler until the thread has started *and* completed, otherwise the
      // serving infrastructure will cancel our ability to make API calls. We're effectively
      // "holding
      // open the door" on the spawned thread's ability to make App Engine API calls.
      // Now set the context class loader to the UserClassLoader for the application
      // and pass control to the Runnable the user provided.
      ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
      Thread.currentThread().setContextClassLoader(appVersion.getClassLoader());
      try {
        eagerRunner.supplyRunnable(runnable);
      } finally {
        Thread.currentThread().setContextClassLoader(oldClassLoader);
      }
      // Wait for the thread to end:
      thread.join();
    }
    upResponse.setError(UPResponse.ERROR.OK_VALUE);
    if (!upResponse.hasHttpResponse()) {
      // If the servlet handler did not write an HTTPResponse
      // already, provide a default one.  This ensures that
      // the code receiving this response does not mistake the
      // lack of an HTTPResponse field for an internal server
      // error (500).
      upResponse.setHttpResponseCodeAndResponse(200, "OK");
    }
  }

  /**
   * A runnable which lets us start running before we even know what to run. The run method first
   * waits to be given a Runnable (from another thread) via the supplyRunnable method, and then we
   * run that.
   */
  public static class EagerRunner implements Runnable {
    private final Exchanger<Runnable> runnableExchanger = new Exchanger<>();

    /**
     * Pass the given runnable to whatever thread's running our run method. This will block until
     * run() is called if it hasn't been already.
     */
    public void supplyRunnable(Runnable runnable) throws InterruptedException, TimeoutException {
      runnableExchanger.exchange(
          runnable, WAIT_FOR_USER_RUNNABLE_DEADLINE.toMillis(), MILLISECONDS);
    }

    @Override
    public void run() {
      // We don't actually know what to run yet! Wait on someone to call supplyRunnable:
      Runnable runnable;
      try {
        runnable =
            runnableExchanger.exchange(
                null, WAIT_FOR_USER_RUNNABLE_DEADLINE.toMillis(), MILLISECONDS);
      } catch (TimeoutException ex) {
        logger.atSevere().withCause(ex).log("Timed out while awaiting runnable");
        return;
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt(); // Restore the interrupted status
        logger.atSevere().withCause(ex).log("Interrupted while awaiting runnable");
        return;
      }

      // Now actually run...
      runnable.run();
    }
  }

  private void dispatchServletRequest() throws Exception {
    upRequestHandler.serviceRequest(upRequest, upResponse);
    if (compressResponse) {
      // try to compress if necessary (http://b/issue?id=3368468)
      try {
        HttpCompression compression = new HttpCompression();
        compression.attemptCompression(upRequest, upResponse);
      } catch (IOException ex) {
        // Zip compression did not work... Response is not compressed.
        logger.atWarning().withCause(ex).log("Error attempting the compression of the response.");
      } catch (RuntimeException ex) {
        // To be on the safe side and keep the request ok
        logger.atWarning().withCause(ex).log("Error attempting the compression of the response.");
      }
    }
  }

  private void handleException(Throwable ex, RequestManager.RequestToken requestToken) {
    // Unwrap ServletException, either from javax or from jakarta exception:
    try {
      java.lang.reflect.Method getRootCause = ex.getClass().getMethod("getRootCause");
      Object rootCause = getRootCause.invoke(ex);
      if (rootCause != null) {
        ex = (Throwable) rootCause;
      }
    } catch (Throwable ignore) {
    }
    String msg = "Uncaught exception from servlet";
    logger.atWarning().withCause(ex).log("%s", msg);
    // Don't use ApiProxy here, because we don't know what state the
    // environment/delegate are in.
    requestToken.addAppLogMessage(ApiProxy.LogRecord.Level.fatal, formatLogLine(msg, ex));

    if (shouldKillCloneAfterException(ex)) {
      logger.atSevere().log("Detected a dangerous exception, shutting down clone nicely.");
      upResponse.setTerminateClone(true);
    }
    UPResponse.ERROR error = UPResponse.ERROR.APP_FAILURE;
    setFailure(upResponse, error, "Unexpected exception from servlet: " + ex);
  }
}
