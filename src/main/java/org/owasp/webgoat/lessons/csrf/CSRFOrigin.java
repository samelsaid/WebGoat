/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Same-origin check shared by the CSRF lesson endpoints: a forged cross-site request has no
 * Origin/Referer that resolves to this host, unlike a request the lesson page itself submitted.
 */
final class CSRFOrigin {

  private CSRFOrigin() {}

  static boolean isSameOrigin(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null) {
      return false;
    }
    String origin = request.getHeader("Origin");
    if (origin != null) {
      return hostMatches(origin, host);
    }
    String referer = request.getHeader("Referer");
    return referer != null && hostMatches(referer, host);
  }

  private static boolean hostMatches(String originOrReferer, String host) {
    String[] parts = originOrReferer.split("/");
    return parts.length > 2 && parts[2].equals(host);
  }
}
