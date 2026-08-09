/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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
  private final String webWolfHost;
  private final String webWolfPort;
  private final String webWolfURL;
  private final String webWolfMailURL;
  private final String resetLinkHost;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort) {
    this.restTemplate = restTemplate;
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
    // Where this application answers, taken from its own configuration.
    this.resetLinkHost = webGoatHost + ":" + webGoatPort;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request, @CurrentUsername String username) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    // A link is issued for exactly one address. Recording that is what lets redeeming it be checked
    // against whoever presents it; before, the list of live links was the only state kept, so
    // holding any link was as good as holding everybody's.
    ResetLinkAssignment.resetLinkOwners.put(resetLink, email);
    String host = request.getHeader(HttpHeaders.HOST);
    if (ResetLinkAssignment.TOM_EMAIL.equals(email)
        && (host.contains(webWolfPort)
            && host.contains(webWolfHost))) { // User indeed changed the host header.
      ResetLinkAssignment.userToTomResetLink.put(username, resetLink);
      fakeClickingLinkEmail(webWolfURL, resetLink);
    } else {
      try {
        sendMailToUser(email, resetLink);
      } catch (Exception e) {
        return informationMessage(this)
            .output("E-mail can't be send. please try again.")
            .build();
      }
    }

    // Asking for a reset is not an accomplishment, and answering the same way for every address
    // keeps this from reporting whether an account exists.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            // The address in the mail is this application's own, never the one the caller claimed
            // to be: a reset link is only ever useful pointing back at the site that issued it.
            .contents(String.format(ResetLinkAssignment.TEMPLATE, resetLinkHost, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String webWolfURL, String resetLink) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity httpEntity = new HttpEntity(httpHeaders);
      new RestTemplate()
          .exchange(
              String.format("%s/PasswordReset/reset/reset-password/%s", webWolfURL, resetLink),
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (Exception e) {
      // don't care
    }
  }
}
