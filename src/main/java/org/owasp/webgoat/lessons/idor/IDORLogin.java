/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  private final LessonSession lessonSession;

  private final Map<String, Map<String, String>> idorUserInfo = new HashMap<>();

  /*
   * The credential this lesson documents, kept as documented.
   *
   * Drawing it from SecureRandom instead made the account impossible to sign in to for anybody,
   * which does not harden anything: "tom" is not an account in this application, it is an entry in
   * the map below that exists so the exercise has somebody to be. The whole subject of the lesson
   * is that a shop stored a weak password in the clear, and the reader is told what it is - it is
   * the exercise's input, not a secret, and it authenticates nothing outside these few endpoints.
   * Withholding it only removed the way in, and every later step of the family is reached through
   * this sign-in.
   *
   * What is worth keeping from the previous attempt is the shape of the comparison, so the digest
   * of the documented value is what gets compared, in constant time.
   */
  private static final String LESSON_USER = "tom";
  private static final String LESSON_PASSWORD = "cat";

  private final byte[] salt = new byte[16];
  private final byte[] passwordHash;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;

    new SecureRandom().nextBytes(salt);
    this.passwordHash = hash(LESSON_PASSWORD);
  }

  public void initIDORInfo() {

    idorUserInfo.put("tom", new HashMap<String, String>());
    idorUserInfo.get("tom").put("id", "2342384");
    idorUserInfo.get("tom").put("color", "yellow");
    idorUserInfo.get("tom").put("size", "small");

    idorUserInfo.put("bill", new HashMap<String, String>());
    idorUserInfo.get("bill").put("id", "2342388");
    idorUserInfo.get("bill").put("color", "brown");
    idorUserInfo.get("bill").put("size", "large");
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    initIDORInfo();

    if (LESSON_USER.equals(username) && MessageDigest.isEqual(passwordHash, hash(password))) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", idorUserInfo.get(username).get("id"));
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    // one answer for both an unknown account and a wrong password
    return failed(this).feedback("idor.login.failure").build();
  }

  private byte[] hash(String password) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      messageDigest.update(salt);
      return messageDigest.digest(
          password == null ? new byte[0] : password.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
