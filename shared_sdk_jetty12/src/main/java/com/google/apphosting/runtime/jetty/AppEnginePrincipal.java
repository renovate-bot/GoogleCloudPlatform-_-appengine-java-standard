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
import java.security.Principal;

/**
 * {@code AppEnginePrincipal} is an implementation of {@link Principal} that represents a logged-in
 * Google App Engine user.
 */
public final class AppEnginePrincipal implements Principal {
  private final User user;

  AppEnginePrincipal(User user) {
    this.user = user;
  }

  public User getUser() {
    return user;
  }

  @Override
  public String getName() {
    if ((user.getFederatedIdentity() != null) && !user.getFederatedIdentity().isEmpty()) {
      return user.getFederatedIdentity();
    }
    return user.getEmail();
  }

  @Override
  public boolean equals(Object other) {
    if (other instanceof AppEnginePrincipal appEnginePrincipal) {
      return user.equals(appEnginePrincipal.user);
    } else {
      return false;
    }
  }

  @Override
  public String toString() {
    return user.toString();
  }

  @Override
  public int hashCode() {
    return user.hashCode();
  }
}
