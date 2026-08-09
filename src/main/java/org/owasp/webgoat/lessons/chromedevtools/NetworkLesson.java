/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.chromedevtools;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Assignment where the user has to look through an HTTP Request using the Developer Tools and find
 * a specific number.
 *
 * @author TMelzer
 * @since 30.11.18
 */
@RestController
@AssignmentHints({"networkHint1", "networkHint2"})
public class NetworkLesson implements AssignmentEndpoint {

  private static final String SESSION_KEY = "networkNum";

  private final LessonSession lessonSession;

  public NetworkLesson(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping(
      value = "/ChromeDevTools/network",
      params = {"network_num", "number"})
  @ResponseBody
  public AttackResult completed(@RequestParam String network_num, @RequestParam String number) {
    Object expected = lessonSession.getValue(SESSION_KEY);
    if (expected != null && expected.equals(number)) {
      return success(this).feedback("network.success").output("").build();
    } else {
      return failed(this).feedback("network.failed").build();
    }
  }

  @PostMapping(path = "/ChromeDevTools/network", params = "networkNum")
  @ResponseBody
  public ResponseEntity<?> ok(@RequestParam String networkNum) {
    lessonSession.setValue(SESSION_KEY, networkNum);
    return ResponseEntity.ok().build();
  }
}
