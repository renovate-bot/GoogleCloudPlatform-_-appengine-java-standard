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

import com.google.appengine.api.users.UserService;
import com.google.appengine.api.users.UserServiceFactory;
import com.google.apphosting.api.ApiProxy;
import com.google.common.flogger.GoogleLogger;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.eclipse.jetty.ee8.nested.Authentication;
import org.eclipse.jetty.ee8.security.ConstraintSecurityHandler;
import org.eclipse.jetty.ee8.security.ServerAuthException;
import org.eclipse.jetty.ee8.security.UserAuthentication;
import org.eclipse.jetty.ee8.security.authentication.DeferredAuthentication;
import org.eclipse.jetty.ee8.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.util.URIUtil;

/**
 * {@code AppEngineAuthentication} is a utility class that can configure a Jetty {@link
 * SecurityHandler} to integrate with the App Engine authentication model.
 *
 * <p>Specifically, it registers a custom {@link Authenticator} instance that knows how to redirect
 * users to a login URL using the {@link UserService}, and a custom {@link UserIdentity} that is
 * aware of the custom roles provided by the App Engine.
 */
public final class AppEngineAuthentication {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /**
   * URLs that begin with this prefix are reserved for internal use by App Engine. We assume that
   * any URL with this prefix may be part of an authentication flow (as in the Dev Appserver).
   */
  private static final String AUTH_URL_PREFIX = "/_ah/";

  private static final String AUTH_METHOD = "Google Login";

  // Keep in sync with com.google.apphosting.runtime.jetty.JettyServletEngineAdapter.
  private static final String SKIP_ADMIN_CHECK_ATTR =
      "com.google.apphosting.internal.SkipAdminCheck";

  /**
   * Any authenticated user is a member of the {@code "*"} role, and any administrators are members
   * of the {@code "admin"} role. Any other roles will be logged and ignored.
   */
  static final String USER_ROLE = "*";

  static final String ADMIN_ROLE = "admin";

  /**
   * Inject custom {@link LoginService} and {@link Authenticator} implementations into the specified
   * {@link ConstraintSecurityHandler}.
   */
  public static void configureSecurityHandler(ConstraintSecurityHandler handler) {

    LoginService loginService = new AppEngineLoginService();
    LoginAuthenticator authenticator = new AppEngineAuthenticator();
    DefaultIdentityService identityService = new DefaultIdentityService();

    // Set allowed roles.
    handler.setRoles(new HashSet<>(Arrays.asList(USER_ROLE, ADMIN_ROLE)));
    handler.setLoginService(loginService);
    handler.setAuthenticator(authenticator);
    handler.setIdentityService(identityService);
    authenticator.setConfiguration(handler);
  }

  /**
   * {@code AppEngineAuthenticator} is a custom {@link Authenticator} that knows how to redirect the
   * current request to a login URL in order to authenticate the user.
   */
  private static class AppEngineAuthenticator extends LoginAuthenticator {

    /**
     * Checks if the request could to the login page.
     *
     * @param uri The uri requested.
     * @return True if the uri starts with "/_ah/", false otherwise.
     */
    private static boolean isLoginOrErrorPage(String uri) {
      return uri.startsWith(AUTH_URL_PREFIX);
    }

    @Override
    public String getAuthMethod() {
      return AUTH_METHOD;
    }

    /**
     * Validate a response. Compare to:
     * j.c.g.apphosting.utils.jetty.AppEngineAuthentication.AppEngineAuthenticator.authenticate().
     *
     * <p>If authentication is required but the request comes from an untrusted ip, 307s the request
     * back to the trusted appserver. Otherwise, it will auth the request and return a login url if
     * needed.
     *
     * <p>From org.eclipse.jetty.server.Authentication:
     *
     * @param servletRequest The request
     * @param servletResponse The response
     * @param mandatory True if authentication is mandatory.
     * @return An Authentication. If Authentication is successful, this will be a {@link
     *     Authentication.User}. If a response has been sent by the Authenticator (which can be done
     *     for both successful and unsuccessful authentications), then the result will implement
     *     {@link Authentication.ResponseSent}. If Authentication is not mandatory, then a {@link
     *     Authentication.Deferred} may be returned.
     * @throws ServerAuthException in an error occurs during authentication.
     */
    @Override
    public Authentication validateRequest(
        ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory)
        throws ServerAuthException {
      HttpServletRequest request = (HttpServletRequest) servletRequest;
      HttpServletResponse response = (HttpServletResponse) servletResponse;
      if (!mandatory) {
        return new DeferredAuthentication(this);
      }
      // Trusted inbound ip, auth headers can be trusted.

      // Use the canonical path within the context for authentication and authorization
      // as this is what is used to generate response content
      String uri = URIUtil.addPaths(request.getServletPath(), request.getPathInfo());

      if (uri == null) {
        uri = "/";
      }
      // Check this before checking if there is a user logged in, so
      // that we can log out properly.  Specifically, watch out for
      // the case where the user logs in, but as a role that isn't
      // allowed to see /*.  They should still be able to log out.
      if (isLoginOrErrorPage(uri) && !DeferredAuthentication.isDeferred(response)) {
        logger.atFine().log(
            "Got %s, returning DeferredAuthentication to imply authentication is in progress.",
            uri);
        return new DeferredAuthentication(this);
      }

      if (request.getAttribute(SKIP_ADMIN_CHECK_ATTR) != null) {
        logger.atFine().log("Returning DeferredAuthentication because of SkipAdminCheck.");
        // Warning: returning DeferredAuthentication here will bypass security restrictions!
        return new DeferredAuthentication(this);
      }

      if (response == null) {
        throw new ServerAuthException("validateRequest called with null response!!!");
      }

      try {
        UserService userService = UserServiceFactory.getUserService();
        // If the user is authenticated already, just create a
        // AppEnginePrincipal or AppEngineFederatedPrincipal for them.
        if (userService.isUserLoggedIn()) {
          UserIdentity user = _loginService.login(null, null, null, null);
          logger.atFine().log("authenticate() returning new principal for %s", user);
          if (user != null) {
            return new UserAuthentication(getAuthMethod(), user);
          }
        }

        if (DeferredAuthentication.isDeferred(response)) {
          return Authentication.UNAUTHENTICATED;
        }

        try {
          logger.atFine().log(
              "Got %s but no one was logged in, redirecting.", request.getRequestURI());
          String url = userService.createLoginURL(getFullURL(request));
          response.sendRedirect(url);
          // Tell Jetty that we've already committed a response here.
          return Authentication.SEND_CONTINUE;
        } catch (ApiProxy.ApiProxyException ex) {
          // If we couldn't get a login URL for some reason, return a 403 instead.
          logger.atSevere().withCause(ex).log("Could not get login URL:");
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return Authentication.SEND_FAILURE;
        }
      } catch (IOException ex) {
        throw new ServerAuthException(ex);
      }
    }

    /*
     * We are not using sessions for authentication.
     */
    @Override
    protected HttpSession renewSession(HttpServletRequest request, HttpServletResponse response) {
      logger.atWarning().log("renewSession throwing an UnsupportedOperationException");
      throw new UnsupportedOperationException();
    }

    /*
     * This seems to only be used by JaspiAuthenticator, all other Authenticators return true.
     */
    @Override
    public boolean secureResponse(
        ServletRequest servletRequest,
        ServletResponse servletResponse,
        boolean isAuthMandatory,
        Authentication.User user) {
      return true;
    }
  }

  /** Returns the full URL of the specified request, including any query string. */
  private static String getFullURL(HttpServletRequest request) {
    StringBuffer buffer = request.getRequestURL();
    if (request.getQueryString() != null) {
      buffer.append('?');
      buffer.append(request.getQueryString());
    }
    return buffer.toString();
  }



  private AppEngineAuthentication() {}
}
