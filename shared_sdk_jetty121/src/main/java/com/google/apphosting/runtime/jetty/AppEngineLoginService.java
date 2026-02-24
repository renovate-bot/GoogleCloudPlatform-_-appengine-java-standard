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

package com.google.apphosting.runtime.jetty;

import com.google.appengine.api.users.User;
import com.google.appengine.api.users.UserService;
import com.google.appengine.api.users.UserServiceFactory;
import com.google.common.flogger.GoogleLogger;
import java.util.function.Function;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.jspecify.annotations.Nullable;

/**
 * {@code AppEngineLoginService} is a custom Jetty {@link LoginService} that is aware of the two
 * special role names implemented by Google App Engine. Any authenticated user is a member of the
 * {@code "*"} role, and any administrators are members of the {@code "admin"} role. Any other
 * roles will be logged and ignored.
 */
public class AppEngineLoginService implements LoginService {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String REALM_NAME = "Google App Engine";

  private IdentityService identityService;

  /**
   * @return Get the name of the login service (aka Realm name)
   */
  @Override
  public String getName() {
    return REALM_NAME;
  }

  @Override
  public UserIdentity login(
      String s, Object o, Request request, Function<Boolean, Session> function) {
    return loadUser();
  }

  /**
   * Creates a new AppEngineUserIdentity based on information retrieved from the Users API.
   *
   * @return A AppEngineUserIdentity if a user is logged in, or null otherwise.
   */
  private @Nullable AppEngineUserIdentity loadUser() {
    UserService userService = UserServiceFactory.getUserService();
    User engineUser = userService.getCurrentUser();
    if (engineUser == null) {
      return null;
    }
    return new AppEngineUserIdentity(new AppEnginePrincipal(engineUser));
  }

  @Override
  public IdentityService getIdentityService() {
    return identityService;
  }

  @Override
  public void logout(UserIdentity user) {
    // Jetty calls this on every request -- even if user is null!
    if (user != null) {
      logger.atFine().log("Ignoring logout call for: %s", user);
    }
  }

  @Override
  public void setIdentityService(IdentityService identityService) {
    this.identityService = identityService;
  }

  @Override
  public boolean validate(UserIdentity user) {
    logger.atInfo().log("validate(%s) throwing UnsupportedOperationException.", user);
    throw new UnsupportedOperationException();
  }
}
