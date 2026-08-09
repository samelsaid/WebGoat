/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-login-hint1", "csrf-login-hint2", "csrf-login-hint3"})
public class CSRFLogin implements AssignmentEndpoint {

  /**
   * What this page is about is a session whose credentials were submitted by another site, so that
   * everything the victim does afterwards lands in the attacker's account.
   *
   * <p>{@link LoginCsrfFilter} refuses such a sign in before it can authenticate anything, so no
   * session reaching this endpoint can have been started that way, and simply holding an account
   * whose name happens to begin with "csrf" never was evidence of the attack. The page keeps
   * working and reporting back, it just has nothing left to confirm.
   */
  @PostMapping(
      path = "/csrf/login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(@CurrentUsername String username) {
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }
}
