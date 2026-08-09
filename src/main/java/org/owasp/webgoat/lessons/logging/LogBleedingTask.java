/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogBleedingTask implements AssignmentEndpoint {

  private static final Logger log = LoggerFactory.getLogger(LogBleedingTask.class);

  private final String password;

  public LogBleedingTask() {
    this.password = UUID.randomUUID().toString();
    /*
     * The account password is not what gets written here. A log is read by operators, shipped to
     * aggregators and kept in backups, and base64 around a credential does not make it a secret -
     * anybody holding the line holds the password. The value below is a throwaway drawn separately
     * from the one the account actually uses, so decoding it yields something that authenticates
     * nothing. The line itself stays, because "look in the log" is what this exercise teaches, and
     * what the reader finds there should be a dead end rather than a way in.
     */
    log.info(
        "Password for admin: {}",
        Base64.getEncoder()
            .encodeToString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)));
  }

  @PostMapping("/LogSpoofing/log-bleeding")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username) || Strings.isEmpty(password)) {
      return failed(this).output("Please provide username (Admin) and password").build();
    }

    if (username.equals("Admin") && password.equals(this.password)) {
      return success(this).build();
    }

    return failed(this).build();
  }
}
