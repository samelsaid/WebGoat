/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // was a hardcoded literal: anyone reading the source could compute a valid hash offline
  // without ever calling the app. Generate per-boot instead so only the app's own hash matches.
  public static final String PASSWORD_SALT_SIMPLE = generateSalt();
  public static final String PASSWORD_SALT_ADMIN = generateSalt();

  private static String generateSalt() {
    byte[] bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return Base64.getEncoder().encodeToString(bytes);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
