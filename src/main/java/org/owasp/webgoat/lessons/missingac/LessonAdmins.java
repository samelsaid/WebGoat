/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Decides whether the caller may use the administrative side of this lesson.
 *
 * <p>The row in the lesson's own table is data, not an authority: anybody may register an account
 * under any name, so a name that happens to match an administrative row would otherwise hand out
 * the role. The role therefore has to be carried by the authenticated principal as well, and that
 * is granted by the application rather than chosen by whoever signs up.
 */
final class LessonAdmins {

  private LessonAdmins() {}

  static boolean isAdmin(MissingAccessControlUserRepository repository, String username) {
    if (username == null || !holdsAdminAuthority()) {
      return false;
    }
    User user = repository.findByUsername(username);
    return user != null && user.isAdmin();
  }

  private static boolean holdsAdminAuthority() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return false;
    }
    for (GrantedAuthority authority : authentication.getAuthorities()) {
      if (WebGoatUser.ROLE_ADMIN.equals(authority.getAuthority())) {
        return true;
      }
    }
    return false;
  }
}
