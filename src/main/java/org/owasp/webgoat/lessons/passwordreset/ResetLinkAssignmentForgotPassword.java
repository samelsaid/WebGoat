/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

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
  private final String webWolfURL;
  private final String webWolfMailURL;
  private final String resetLinkHost;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
    // Where this application actually answers, decided by its own configuration.
    this.resetLinkHost = webGoatHost + ":" + webGoatPort;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, @CurrentUsername String username) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    if (ResetLinkAssignment.TOM_EMAIL.equals(email)) {
      /*
       * Tom is fictional and exists only inside this lesson: his "password" lives in a per-learner
       * map, not in the user store, so nothing outside the exercise can be reached through him.
       * The lesson therefore keeps simulating him opening his own link.
       *
       * What used to decide this branch was the Host header - if the client claimed to be WebWolf,
       * the application handed over a link belonging to somebody else. That decision is gone: the
       * header no longer selects a recipient, so no header a client can write redirects another
       * account's reset link.
       */
      ResetLinkAssignment.userToTomResetLink.put(username, resetLink);
      fakeClickingLinkEmail(resetLink);
    } else {
      try {
        sendMailToUser(email, resetLink);
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            // The address in the mail is this application's own, never the one the request asked
            // for: a link is only useful if it points at the site that issued it.
            .contents(String.format(ResetLinkAssignment.TEMPLATE, resetLinkHost, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String resetLink) {
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
