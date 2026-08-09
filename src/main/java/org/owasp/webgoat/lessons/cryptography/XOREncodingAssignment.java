/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"crypto-encoding-xor.hints.1"})
public class XOREncodingAssignment implements AssignmentEndpoint {

  /*
   * The value the exercise asks the reader to reverse is printed in the lesson itself, as
   * {xor}Oz4rPj0+LDovPiwsKDAtOw== , and undoing that encoding is the whole assignment. It is a
   * made up sample string, not a credential: nothing in WebGoat or anywhere else accepts it, so
   * publishing it discloses nothing. The point the lesson makes - that a WebSphere {xor} value is
   * an encoding anybody can undo and never a way to protect a password - is what the reader is
   * meant to walk away with, and it only lands if the exercise can actually be completed.
   */
  private static final String PUBLISHED_SAMPLE_PASSWORD = "databasepassword";

  @PostMapping("/crypto/encoding/xor")
  @ResponseBody
  public AttackResult completed(@RequestParam String answer_pwd1) {
    if (answer_pwd1 != null && answer_pwd1.equals(PUBLISHED_SAMPLE_PASSWORD)) {
      return success(this).feedback("crypto-encoding-xor.success").build();
    }
    return failed(this).feedback("crypto-encoding-xor.empty").build();
  }
}
