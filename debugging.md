<!--
 Copyright 2021 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

# Google App Engine Java Debugging Guide

## Jetty Debug Logging

To enable debug logging in your web application, add a JUL `logging.properties` file under your application's `WEB-INF` directory.

In your `appengine-web.xml` file, specify the location of the logging file as a system property:

```xml
<system-properties>
  <property name="java.util.logging.config.file" value="WEB-INF/logging.properties"/>
</system-properties>
```

For runtimes using the Jetty 9.4 code path (Java 8 - Java 17), there is a known issue where debug logging will not be output unless full debug logging is enabled with `.level=ALL`.

In the Java 21 runtime with Jetty 12, more granular debug logging is available. For example:
```
.level=INFO
org.eclipse.jetty.session.level=ALL
org.eclipse.jetty.server.level=ALL
```

## Jetty Server Dump

A Jetty Server Dump is useful for debugging issues by providing details about Jetty components and their configuration, including thread pools, connectors, contexts, classloaders, servlets, and more.

To enable a Jetty Server Dump after the `AppEngineWebAppContext` is started (which may occur after the first request in RPC mode), use the following system property:

```xml
<system-properties>
  <property name="jetty.server.dumpAfterStart" value="true"/>
</system-properties>
```

