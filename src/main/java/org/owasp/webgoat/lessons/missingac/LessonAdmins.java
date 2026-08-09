/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

/**
 * Decides whether the caller may use the administrative side of this lesson.
 *
 * <p>The role lives in the lesson's own table, keyed by the authenticated username, and is never
 * taken from the request itself. A caller only holds it once a row for their own username has
 * been recorded as admin through the lesson's intended (exploitable) path; it can't be asserted
 * simply by naming an admin in the request.
 */
final class LessonAdmins {

  private LessonAdmins() {}

  static boolean isAdmin(MissingAccessControlUserRepository repository, String username) {
    if (username == null) {
      return false;
    }
    User user = repository.findByUsername(username);
    return user != null && user.isAdmin();
  }
}
