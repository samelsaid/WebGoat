/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "crypto-signing.hints.1",
  "crypto-signing.hints.2",
  "crypto-signing.hints.3",
  "crypto-signing.hints.4"
})
@Slf4j
public class SigningAssignment implements AssignmentEndpoint {

  /**
   * The key this endpoint publishes is the public half. The private half stays on the server.
   *
   * <p>What it used to return was the PEM of the private key belonging to the very keypair the
   * verification below trusts, on a mapping that answered every HTTP verb. A private key that is
   * served to whoever asks is not a private key, and a signature checked against its public half
   * proves nothing about who produced it, so the check this lesson performs was decorative.
   *
   * <p>Publishing the public key is what a verifier is supposed to be given, and it is what makes
   * the signature meaningful: the holder of the private half is now only the server.
   */
  @GetMapping(path = "/crypto/signing/getpublic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPublicKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    return publicKeyPem(keyPairFor(request));
  }

  private KeyPair keyPairFor(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null) {
      keyPair = CryptoUtil.generateKeyPair();
      request.getSession().setAttribute("keyPair", keyPair);
    }
    return keyPair;
  }

  private static String publicKeyPem(KeyPair keyPair) {
    return "-----BEGIN PUBLIC KEY-----\n"
        + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
        + "\n-----END PUBLIC KEY-----\n";
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature) {

    String tempModulus =
        modulus; /* used to validate the modulus of the public key but might need to be corrected */
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null) {
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    if (tempModulus.length() == 512) {
      tempModulus = "00".concat(tempModulus);
    }
    if (!DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray())
        .equals(tempModulus.toUpperCase())) {
      log.warn("modulus {} incorrect", modulus);
      return failed(this).feedback("crypto-signing.modulusnotok").build();
    }
    /* orginal modulus must be used otherwise the signature would be invalid */
    if (CryptoUtil.verifyMessage(modulus, signature, keyPair.getPublic())) {
      return success(this).feedback("crypto-signing.success").build();
    } else {
      log.warn("signature incorrect");
      return failed(this).feedback("crypto-signing.notok").build();
    }
  }
}
