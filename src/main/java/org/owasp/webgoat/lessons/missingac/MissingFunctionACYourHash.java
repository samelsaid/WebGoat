/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "access-control.hash.hint1",
  "access-control.hash.hint2",
  "access-control.hash.hint3",
  "access-control.hash.hint4",
  "access-control.hash.hint5"
})
public class MissingFunctionACYourHash implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACYourHash(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/user-hash",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult simple(String userHash) {
    // The disclosure this lesson is about is /access-control/users handing the hash list to a
    // caller who is not an administrator; that stays closed. This endpoint only compares a hash
    // the caller already supplied, so it reveals nothing on its own.
    User user = userRepository.findByUsername("Jerry");
    if (user == null) {
      return failed(this).build();
    }
    DisplayUser displayUser = new DisplayUser(user, PASSWORD_SALT_SIMPLE);
    if (displayUser.getUserHash().equals(userHash)) {
      return success(this).feedback("access-control.hash.success").build();
    } else {
      return failed(this).build();
    }
  }
}
