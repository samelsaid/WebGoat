/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final String SESSION_PASSWORD_ATTR = "insecureLoginPassword";
  private static final SecureRandom RANDOM = new SecureRandom();

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String username, @RequestParam String password, HttpSession session) {
    // password is per-session so a captured/replayed constant can't pass the check
    Object sessionPassword = session.getAttribute(SESSION_PASSWORD_ATTR);
    if (sessionPassword == null) {
      return failed(this).build();
    }
    if (constantTimeEquals(username, "CaptainJack")
        && constantTimeEquals(password, (String) sessionPassword)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  private boolean constantTimeEquals(String actual, String expected) {
    return MessageDigest.isEqual(
        actual.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public String login(HttpSession session) {
    // issue an unguessable per-session password, still sent in the clear
    String password = (String) session.getAttribute(SESSION_PASSWORD_ATTR);
    if (password == null) {
      password = "BlackPearl-" + Long.toHexString(RANDOM.nextLong());
      session.setAttribute(SESSION_PASSWORD_ATTR, password);
    }
    return password;
  }
}
