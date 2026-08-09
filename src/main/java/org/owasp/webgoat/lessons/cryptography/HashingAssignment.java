/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.xml.bind.DatatypeConverter;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"crypto-hashing.hints.1", "crypto-hashing.hints.2"})
public class HashingAssignment implements AssignmentEndpoint {
  public static final String[] SECRETS = {"secret", "admin", "password", "123456", "passw0rd"};
  private static final SecureRandom RANDOM = new SecureRandom();

  @RequestMapping(path = "/crypto/hashing/md5", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getMd5(HttpServletRequest request) throws NoSuchAlgorithmException {

    String md5Hash = (String) request.getSession().getAttribute("md5Hash");
    if (md5Hash == null) {

      String secret = SECRETS[RANDOM.nextInt(SECRETS.length)];

      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(secret.getBytes());
      byte[] digest = md.digest();
      md5Hash = DatatypeConverter.printHexBinary(digest).toUpperCase();
      request.getSession().setAttribute("md5Hash", md5Hash);
      request.getSession().setAttribute("md5Secret", secret);
    }
    return md5Hash;
  }

  @RequestMapping(path = "/crypto/hashing/sha256", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSha256(HttpServletRequest request) throws NoSuchAlgorithmException {

    String sha256 = (String) request.getSession().getAttribute("sha256");
    if (sha256 == null) {
      String secret = SECRETS[RANDOM.nextInt(SECRETS.length)];
      sha256 = getHash(secret, "SHA-256");
      request.getSession().setAttribute("sha256Hash", sha256);
      request.getSession().setAttribute("sha256Secret", secret);
    }
    return sha256;
  }

  @PostMapping("/crypto/hashing")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_pwd1,
      @RequestParam String answer_pwd2) {

    String md5Secret = (String) request.getSession().getAttribute("md5Secret");
    String sha256Secret = (String) request.getSession().getAttribute("sha256Secret");

    if (answer_pwd1 != null && answer_pwd2 != null) {
      boolean pwd1Ok = secretEquals(answer_pwd1, md5Secret);
      boolean pwd2Ok = secretEquals(answer_pwd2, sha256Secret);
      if (pwd1Ok && pwd2Ok) {
        return success(this).feedback("crypto-hashing.success").build();
      } else if (pwd1Ok || pwd2Ok) {
        return failed(this).feedback("crypto-hashing.oneok").build();
      }
    }
    return failed(this).feedback("crypto-hashing.empty").build();
  }

  // constant-time comparison to avoid leaking the secret via response timing
  private static boolean secretEquals(String answer, String secret) {
    if (secret == null) {
      return false;
    }
    return MessageDigest.isEqual(
        answer.getBytes(StandardCharsets.UTF_8), secret.getBytes(StandardCharsets.UTF_8));
  }

  public static String getHash(String secret, String algorithm) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(secret.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest).toUpperCase();
  }
}
