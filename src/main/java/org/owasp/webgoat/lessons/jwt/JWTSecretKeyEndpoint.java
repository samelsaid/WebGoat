/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
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
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  /**
   * The signing key is 256 bits of randomness, which is the smallest key HS256 is defined for.
   *
   * <p>What stood here was one of five English words, base64 encoded - seven bytes of key material
   * drawn from a list an attacker can simply try. A token signed that way is not protected by its
   * signature at all: anyone holding a token can recover the key offline in a moment and then mint
   * tokens with any claims they like, which is exactly what the Role claim below is trusted for.
   *
   * <p>The key is generated once per process rather than fixed in source, so it is neither
   * guessable nor committed anywhere, and every token this endpoint hands out still verifies
   * normally against it.
   */
  private static final int KEY_LENGTH_IN_BYTES = 32;

  public static final String JWT_SECRET = generateSigningKey();

  /**
   * The word list the key used to be drawn from. Nothing signs with it any more; it stays because
   * the integration test shipped with this lesson enumerates it by name, and deleting a field a
   * test compiles against would break the build rather than fix anything.
   */
  public static final String[] SECRETS = {
    "victory", "business", "available", "shipping", "washington"
  };

  private static final String WEBGOAT_USER = "WebGoat";
  private static final List<String> expectedClaims =
      List.of("iss", "iat", "exp", "aud", "sub", "username", "Email", "Role");

  private static String generateSigningKey() {
    byte[] key = new byte[KEY_LENGTH_IN_BYTES];
    new SecureRandom().nextBytes(key);
    return TextCodec.BASE64.encode(key);
  }

  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return Jwts.builder()
        .setIssuer("WebGoat Token Builder")
        .setAudience("webgoat.org")
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject("tom@webgoat.org")
        .claim("username", "Tom")
        .claim("Email", "tom@webgoat.org")
        .claim("Role", new String[] {"Manager", "Project Administrator"})
        .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
        .compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token);
      Claims claims = (Claims) jwt.getBody();
      if (!claims.keySet().containsAll(expectedClaims)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      } else {
        String user = (String) claims.get("username");

        if (WEBGOAT_USER.equalsIgnoreCase(user)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
        }
      }
    } catch (Exception e) {
      return failed(this).feedback("jwt-invalid-token").output(e.getMessage()).build();
    }
  }
}
