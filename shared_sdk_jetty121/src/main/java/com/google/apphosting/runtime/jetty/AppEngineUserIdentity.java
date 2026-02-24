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
import java.security.Principal;
import java.util.Objects;
import javax.security.auth.Subject;
import org.eclipse.jetty.security.UserIdentity;

/**
 * {@code AppEngineUserIdentity} is an implementation of {@link UserIdentity} that represents a
 * logged-in Google App Engine user.
 */
public class AppEngineUserIdentity implements UserIdentity {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final AppEnginePrincipal userPrincipal;

  public AppEngineUserIdentity(AppEnginePrincipal userPrincipal) {
    this.userPrincipal = userPrincipal;
  }

  /*
   * Only used by jaas and jaspi.
   */
  @Override
  public Subject getSubject() {
    logger.atInfo().log("getSubject() throwing UnsupportedOperationException.");
    throw new UnsupportedOperationException();
  }

  @Override
  public Principal getUserPrincipal() {
    return userPrincipal;
  }

  @Override
  public boolean isUserInRole(String role) {
    UserService userService = UserServiceFactory.getUserService();
    if (userPrincipal == null) {
      logger.atInfo().log("isUserInRole() called with null principal.");
      return false;
    }

    if (Objects.equals(role, AppEngineAuthentication.USER_ROLE)) {
      return true;
    }

    if (Objects.equals(role, AppEngineAuthentication.ADMIN_ROLE)) {
      User user = userPrincipal.getUser();
      if (user.equals(userService.getCurrentUser())) {
        return userService.isUserAdmin();
      } else {
        // TODO: I'm not sure this will happen in
        //   practice. If it does, we may need to pass an
        //   application's admin list down somehow.
        logger.atSevere().log("Cannot tell if non-logged-in user %s is an admin.", user);
        return false;
      }
    } else {
      logger.atWarning().log("Unknown role: %s.", role);
      return false;
    }
  }

  @Override
  public String toString() {
    return AppEngineUserIdentity.class.getSimpleName() + "('" + userPrincipal + "')";
  }
}
