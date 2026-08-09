/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.security.SecureRandom;

public interface SolutionConstants {

  // generated at startup (instead of a fixed literal) so the base secret can't be read
  // straight out of this (public) source file; "1234" stays as the placeholder the pincode
  // gets substituted into, see Assignment1
  String PASSWORD = generatePassword();

  static String generatePassword() {
    String alphabet = "abcdefghijklmnopqrstuvwxyz";
    SecureRandom random = new SecureRandom();
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 10; i++) {
      sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
    }
    return "!!" + sb + "_1234!!";
  }
}
