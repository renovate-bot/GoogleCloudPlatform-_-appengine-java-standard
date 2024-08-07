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
package com.google.apphosting.runtime.jetty9;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.lessThan;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentProvider;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Response;
import org.eclipse.jetty.client.api.Result;
import org.eclipse.jetty.client.util.ByteBufferContentProvider;
import org.eclipse.jetty.client.util.DeferredContentProvider;
import org.eclipse.jetty.client.util.InputStreamContentProvider;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.Utf8StringBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SizeLimitIgnoreTest extends JavaRuntimeViaHttpBase {
  @Parameterized.Parameters
  public static List<Object[]> data() {
    return Arrays.asList(
        new Object[][] {
          {"jetty94", false},
          {"ee8", false},
          {"ee10", false},
          {"ee8", true},
          {"ee10", true},
        });
  }

  private static final int MAX_SIZE = 32 * 1024 * 1024;
  @Rule public TemporaryFolder temp = new TemporaryFolder();
  private final HttpClient httpClient = new HttpClient();
  private final boolean httpMode;
  private final String environment;
  private RuntimeContext<?> runtime;

  public SizeLimitIgnoreTest(String environment, boolean httpMode) {
    this.environment = environment;
    this.httpMode = httpMode;
    System.setProperty("appengine.use.HttpConnector", Boolean.toString(httpMode));
    System.setProperty("appengine.ignore.responseSizeLimit", "true");
  }

  @Before
  public void before() throws Exception {
    String app = "sizelimit" + environment;
    copyAppToDir(app, temp.getRoot().toPath());
    httpClient.start();
    runtime = runtimeContext();
    assertEnvironment();
    System.err.println("==== Using Environment: " + environment + " " + httpMode + " ====");
  }

  @After
  public void after() throws Exception {
    httpClient.stop();
    runtime.close();
  }

  @Test
  public void testResponseContentBelowMaxLength() throws Exception {
    long contentLength = MAX_SIZE;
    String url = runtime.jettyUrl("/?size=" + contentLength);
    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    AtomicLong contentReceived = new AtomicLong();
    httpClient
        .newRequest(url)
        .onResponseContentAsync(
            (response, content, callback) -> {
              contentReceived.addAndGet(content.remaining());
              callback.succeeded();
            })
        .header("setCustomHeader", "true")
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.OK_200));
    assertThat(contentReceived.get(), equalTo(contentLength));
    assertThat(result.getResponse().getHeaders().get("custom-header"), equalTo("true"));
  }

  @Test
  public void testResponseContentAboveMaxLength() throws Exception {
    long contentLength = MAX_SIZE + 1;
    String url = runtime.jettyUrl("/?size=" + contentLength);
    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    AtomicLong contentReceived = new AtomicLong();
    httpClient
        .newRequest(url)
        .onResponseContentAsync(
            (response, content, callback) -> {
              contentReceived.addAndGet(content.remaining());
              callback.succeeded();
            })
        .header("setCustomHeader", "true")
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.OK_200));
    assertThat(contentReceived.get(), equalTo(contentLength));
    assertThat(result.getResponse().getHeaders().get("custom-header"), equalTo("true"));
  }

  @Test
  public void testResponseContentBelowMaxLengthGzip() throws Exception {
    long contentLength = MAX_SIZE;
    String url = runtime.jettyUrl("/?size=" + contentLength);
    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    AtomicLong contentReceived = new AtomicLong();
    httpClient.getContentDecoderFactories().clear();
    httpClient
        .newRequest(url)
        .onResponseContentAsync(
            (response, content, callback) -> {
              contentReceived.addAndGet(content.remaining());
              callback.succeeded();
            })
        .header(HttpHeader.ACCEPT_ENCODING, "gzip")
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getHeaders().get(HttpHeader.CONTENT_ENCODING), equalTo("gzip"));
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.OK_200));
    assertThat(contentReceived.get(), lessThan(contentLength));
  }

  @Test
  public void testResponseContentAboveMaxLengthGzip() throws Exception {
    long contentLength = MAX_SIZE + 1;
    String url = runtime.jettyUrl("/?size=" + contentLength);
    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    AtomicLong contentReceived = new AtomicLong();
    httpClient.getContentDecoderFactories().clear();
    httpClient
        .newRequest(url)
        .onResponseContentAsync(
            (response, content, callback) -> {
              contentReceived.addAndGet(content.remaining());
              callback.succeeded();
            })
        .header(HttpHeader.ACCEPT_ENCODING, "gzip")
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getHeaders().get(HttpHeader.CONTENT_ENCODING), equalTo("gzip"));
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.OK_200));
    assertThat(contentReceived.get(), lessThan(contentLength));
  }

  @Test
  public void testRequestContentBelowMaxLength() throws Exception {
    int contentLength = MAX_SIZE;

    byte[] data = new byte[contentLength];
    Arrays.fill(data, (byte) 'X');
    ContentProvider content = new ByteBufferContentProvider(BufferUtil.toBuffer(data));
    String url = runtime.jettyUrl("/");
    ContentResponse response = httpClient.newRequest(url).content(content).send();

    assertThat(response.getStatus(), equalTo(HttpStatus.OK_200));
    assertThat(
        response.getContentAsString(), containsString("RequestContentLength: " + contentLength));
  }

  @Test
  public void testRequestContentAboveMaxLength() throws Exception {
    int contentLength = MAX_SIZE + 1;

    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    byte[] data = new byte[contentLength];
    Arrays.fill(data, (byte) 'X');
    Utf8StringBuilder received = new Utf8StringBuilder();
    ContentProvider content = new ByteBufferContentProvider(BufferUtil.toBuffer(data));
    String url = runtime.jettyUrl("/");
    httpClient
        .newRequest(url)
        .content(content)
        .onResponseContentAsync(
            (response, content1, callback) -> {
              received.append(content1);
              callback.succeeded();
            })
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.PAYLOAD_TOO_LARGE_413));

    // If there is no Content-Length header the SizeLimitHandler fails the response as well.
    if (result.getResponseFailure() == null) {
      assertThat(received.toString(), containsString("Request body is too large"));
    }
  }

  @Test
  public void testRequestContentBelowMaxLengthGzip() throws Exception {
    int contentLength = MAX_SIZE;

    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    byte[] data = new byte[contentLength];
    Arrays.fill(data, (byte) 'X');
    Utf8StringBuilder received = new Utf8StringBuilder();
    ContentProvider content = new InputStreamContentProvider(gzip(data));

    String url = runtime.jettyUrl("/");
    httpClient
        .newRequest(url)
        .content(content)
        .onResponseContentAsync(
            (response, content1, callback) -> {
              received.append(content1);
              callback.succeeded();
            })
        .header(HttpHeader.CONTENT_ENCODING, "gzip")
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.OK_200));
    assertThat(received.toString(), containsString("RequestContentLength: " + contentLength));
  }

  @Test
  public void testRequestContentAboveMaxLengthGzip() throws Exception {
    int contentLength = MAX_SIZE + 1;

    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    byte[] data = new byte[contentLength];
    Arrays.fill(data, (byte) 'X');
    Utf8StringBuilder received = new Utf8StringBuilder();
    ContentProvider content = new InputStreamContentProvider(gzip(data));

    String url = runtime.jettyUrl("/");
    httpClient
        .newRequest(url)
        .content(content)
        .onResponseContentAsync(
            (response, content1, callback) -> {
              received.append(content1);
              callback.succeeded();
            })
        .header(HttpHeader.CONTENT_ENCODING, "gzip")
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    assertThat(result.getResponse().getStatus(), equalTo(HttpStatus.PAYLOAD_TOO_LARGE_413));

    // If there is no Content-Length header the SizeLimitHandler fails the response as well.
    if (result.getResponseFailure() == null) {
      assertThat(received.toString(), containsString("Request body is too large"));
    }
  }

  @Test
  public void testResponseContentLengthHeader() throws Exception {
    long contentLength = MAX_SIZE + 1;
    String url = runtime.jettyUrl("/?setContentLength=" + contentLength);
    httpClient.getContentDecoderFactories().clear();
    ContentResponse response = httpClient.newRequest(url).send();

    assertThat(response.getStatus(), equalTo(HttpStatus.INTERNAL_SERVER_ERROR_500));

    // No content is sent on the Jetty 9.4 runtime.
    if (!Objects.equals(environment, "jetty94")) {
      assertThat(response.getContentAsString(), containsString("IllegalStateException"));
    }
  }

  @Test
  public void testRequestContentLengthHeader() throws Exception {
    CompletableFuture<Result> completionListener = new CompletableFuture<>();
    DeferredContentProvider provider = new DeferredContentProvider(ByteBuffer.allocate(1));
    int contentLength = MAX_SIZE + 1;
    String url = runtime.jettyUrl("/");
    Utf8StringBuilder received = new Utf8StringBuilder();
    httpClient
        .newRequest(url)
        .header(HttpHeader.CONTENT_LENGTH, Long.toString(contentLength))
        .header("foo", "bar")
        .content(provider)
        .onResponseContentAsync(
            (response, content, callback) -> {
              received.append(content);
              callback.succeeded();
              provider.close();
            })
        .send(completionListener::complete);

    Result result = completionListener.get(5, TimeUnit.SECONDS);
    Response response = result.getResponse();
    assertThat(response.getStatus(), equalTo(HttpStatus.PAYLOAD_TOO_LARGE_413));

    // If there is no Content-Length header the SizeLimitHandler fails the response as well.
    if (result.getResponseFailure() == null) {
      assertThat(received.toString(), containsString("Request body is too large"));
    }
  }

  private RuntimeContext<?> runtimeContext() throws Exception {
    RuntimeContext.Config<?> config =
        RuntimeContext.Config.builder().setApplicationPath(temp.getRoot().toString()).build();
    return RuntimeContext.create(config);
  }

  private void assertEnvironment() throws Exception {
    String match;
    switch (environment) {
      case "jetty94":
        match = "org.eclipse.jetty.server.Request";
        break;
      case "ee8":
        match = "org.eclipse.jetty.ee8";
        break;
      case "ee10":
        match = "org.eclipse.jetty.ee10";
        break;
      default:
        throw new IllegalArgumentException(environment);
    }

    String runtimeUrl = runtime.jettyUrl("/?getRequestClass=true");
    ContentResponse response = httpClient.GET(runtimeUrl);
    assertThat(response.getContentAsString(), containsString(match));
  }

  private static InputStream gzip(byte[] data) throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {
      gzipOutputStream.write(data);
    }
    return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
  }
}
