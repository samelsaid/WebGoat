/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webGoatAuthority;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate, @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    // the template supplies the scheme and context path, so this is just host:port,
    // taken from configuration and never from the Host header the caller writes
    this.webGoatAuthority = webGoatHost + ":" + webGoatPort;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    ResetLinkAssignment.resetLinkOwners.put(resetLink, email);
    try {
      // Only a notification goes out. The token stays here, so neither the Host header (which
      // the client writes) nor access to the mailbox yields a link that works.
      sendMailToUser(email, resetLink);
    } catch (Exception e) {
      return failed(this).output("E-mail can't be send. please try again.").build();
    }
    // The same answer for every address: no account enumeration, and no link for an account
    // that is not yours.
    // Sending the mail is what this step asks for, so saying so is part of the step
    // working. What is fixed is the address the link carries and who can redeem it.
    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, webGoatAuthority, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }
}
