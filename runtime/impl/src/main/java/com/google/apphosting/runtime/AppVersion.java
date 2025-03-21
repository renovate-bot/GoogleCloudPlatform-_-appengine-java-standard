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

import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static java.nio.file.FileVisitOption.FOLLOW_LINKS;

import com.google.apphosting.base.AppVersionKey;
import com.google.apphosting.base.protos.AppinfoPb.AppInfo;
import com.google.auto.value.AutoBuilder;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.jspecify.annotations.Nullable;

/**
 * {@code AppVersion} encapsulates the configuration information
 * associated with one version of a particular application.  Do not
 * construct a {@code AppVersion} directly, instead use {@link
 * AppVersionFactory}.
 *
 * @see AppVersionFactory
 * @see AppVersionKey
 *
 */
public class AppVersion {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  /**
   * We assume that this string is prepended to the path for any
   * blobs.  We also assume that there is a fallthrough handler that
   * tries to serve all requests as __static__/\1.
   */
  private static final String STATIC_PREFIX = "__static__/";

  private final AppVersionKey appVersionKey;
  private final File rootDirectory;
  private final ClassLoader classLoader;
  private final ApplicationEnvironment environment;
  private final ImmutableSet<String> resourceFiles;
  private final Set<String> staticFiles;
  private final SessionsConfig sessionsConfig;
  private final String publicRoot;
  private final ThreadGroupPool threadGroupPool;

  /** Return a builder for an AppVersion instance. */
  public static Builder builder() {
    return new AutoBuilder_AppVersion_Builder();
  }

  /** Builder for AppVersion. */
  @AutoBuilder
  public abstract static class Builder {
    Builder() {}

    public abstract Builder setAppVersionKey(AppVersionKey x);

    public abstract Builder setAppInfo(AppInfo x);

    public abstract Builder setRootDirectory(File x);

    public abstract Builder setClassLoader(ClassLoader x);

    public abstract Builder setEnvironment(ApplicationEnvironment x);

    public abstract Builder setSessionsConfig(SessionsConfig x);

    public abstract Builder setPublicRoot(String x);

    public abstract Builder setThreadGroupPool(ThreadGroupPool x);

    public abstract AppVersion build();
  }

  AppVersion(
      @Nullable AppVersionKey appVersionKey,
      @Nullable AppInfo appInfo,
      @Nullable File rootDirectory,
      @Nullable ClassLoader classLoader,
      @Nullable ApplicationEnvironment environment,
      @Nullable SessionsConfig sessionsConfig,
      String publicRoot,
      @Nullable ThreadGroupPool threadGroupPool) {
    this.appVersionKey = appVersionKey;
    this.rootDirectory = rootDirectory;
    this.classLoader = classLoader;
    this.environment = environment;
    this.resourceFiles = extractResourceFiles(appInfo);
    this.staticFiles = extractStaticFiles(appInfo);
    this.sessionsConfig = sessionsConfig;
    if (!publicRoot.isEmpty()) {
      publicRoot = publicRoot.substring(1) + "/";
    }
    this.publicRoot = publicRoot;
    this.threadGroupPool = threadGroupPool;
  }

  /**
   * Returns the {@link AppVersionKey} that can be used as an
   * identifier for this {@link AppVersion}.
   */
  public AppVersionKey getKey() {
    return appVersionKey;
  }

  /**
   * Returns the top-level directory under which all application
   * version resource files are made available.
   */
  public File getRootDirectory() {
    return rootDirectory;
  }

  /**
   * Returns the custom {@link ClassLoader} that will safely load
   * classes and resource files that were published along with this
   * application version.
   */
  public ClassLoader getClassLoader() {
    return classLoader;
  }

  /**
   * Returns the environment which was configured for the application.
   */
  public ApplicationEnvironment getEnvironment() {
    return environment;
  }

  public SessionsConfig getSessionsConfig() {
    return sessionsConfig;
  }

  /**
   * Returns true if {@code path} is a resource file that was uploaded
   * as part of this application.
   */
  public boolean isResourceFile(String path) {
    return resourceFiles.contains(publicRoot + path);
  }

  /**
   * Returns true if {@code path} is a static file that was uploaded
   * to BlobStore for use by this application.
   */
  public boolean isStaticFile(String path) {
    return staticFiles.contains(STATIC_PREFIX + publicRoot + path);
  }

  /**
   * Returns the parent directory for all static and resource files.
   */
  public String getPublicRoot() {
    return publicRoot;
  }

  public ThreadGroupPool getThreadGroupPool() {
    return threadGroupPool;
  }

  private ImmutableSet<String> extractResourceFiles(AppInfo appInfo) {

    if (!appInfo.getFileList().isEmpty()) {
      return appInfo.getFileList().stream().map(AppInfo.File::getPath).collect(toImmutableSet());
    }
    if (getRootDirectory() != null) {
      Path app = FileSystems.getDefault().getPath(getRootDirectory().getAbsolutePath());
      if (Files.isDirectory(app)) {
        try (Stream<Path> stream = Files.walk(app, FOLLOW_LINKS)) {
          // We correct possible Windows style paths with /.
          return stream
              .map(path -> app.relativize(path).toString().replace('\\', '/'))
              .collect(toImmutableSet());
        } catch (IOException ex) {
          logger.atWarning().withCause(ex).log("Cannot list files in : %s", app);
        }
      }
    }
    return ImmutableSet.of();
  }

  private static Set<String> extractStaticFiles(AppInfo appInfo) {
    Set<String> files = new HashSet<>();
    for (AppInfo.Blob blob : appInfo.getBlobList()) {
      files.add(blob.getPath());
    }
    return files;
  }
}
