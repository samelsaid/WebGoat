/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.codec.Hex;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  // trailing bytes used to just be trimmed off, never verified, so any username could be
  // forged; sign the value with a server-only HMAC key and check it in constant time instead
  private static final String HMAC_ALGO = "HmacSHA256";
  private static final byte[] KEY = new byte[32];

  static {
    new SecureRandom().nextBytes(KEY);
  }

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String username = value.toLowerCase();
    String signed = username + ":" + hexEncode(hmac(username));
    return base64Encode(signed);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String decoded = base64Decode(encodedValue);
    int separator = decoded.lastIndexOf(':');
    if (separator < 0) {
      throw new IllegalArgumentException("Invalid cookie value");
    }

    String username = decoded.substring(0, separator);
    String mac = decoded.substring(separator + 1);
    byte[] expectedMac = hexEncode(hmac(username)).getBytes(StandardCharsets.UTF_8);
    if (!MessageDigest.isEqual(expectedMac, mac.getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException("Invalid cookie value");
    }
    return username;
  }

  private static byte[] hmac(final String value) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGO);
      mac.init(new SecretKeySpec(KEY, HMAC_ALGO));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static String hexEncode(final byte[] value) {
    return new String(Hex.encode(value));
  }

  private static String base64Encode(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getDecoder().decode(value.getBytes(StandardCharsets.UTF_8));
    return new String(decoded, StandardCharsets.UTF_8);
  }
}
