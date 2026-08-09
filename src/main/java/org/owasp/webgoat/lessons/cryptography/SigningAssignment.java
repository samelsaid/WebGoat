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
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
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
   * Issuing the key is a POST because handing out private key material is an action, not a page
   * read.
   *
   * <p>As a method-agnostic mapping this answered any verb, so any request that reached the
   * application - a cross-origin fetch, an image tag, a crawler, a link someone was sent - came
   * back with a usable RSA private key, and the signature this lesson verifies is only worth
   * anything while the key behind it is unavailable to whoever is being checked. Requiring a POST
   * means the browser will not issue it cross-origin without a preflight, it is never cached, and
   * it is not something a URL alone can trigger. The lesson still hands the reader the key it
   * documents, over the same path, on the request the page makes.
   */
  @PostMapping(path = "/crypto/signing/getprivate", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getPrivateKey(HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    String privateKey = (String) request.getSession().getAttribute("privateKeyString");
    if (privateKey == null) {
      KeyPair keyPair = CryptoUtil.generateKeyPair();
      privateKey = CryptoUtil.getPrivateKeyInPEM(keyPair);
      request.getSession().setAttribute("privateKeyString", privateKey);
      request.getSession().setAttribute("keyPair", keyPair);
    }
    return privateKey;
  }

  @PostMapping("/crypto/signing/verify")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestParam String modulus, @RequestParam String signature) {

    String tempModulus =
        modulus; /* used to validate the modulus of the public key but might need to be corrected */
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    if (keyPair == null) {
      // No key has been handed to this session yet, so there is nothing to verify against.
      // Dereferencing it threw out of the handler instead, which turns a request arriving in the
      // wrong order - or one sent directly, without loading the page first - into a 500 and an
      // error page rather than an answer.
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
