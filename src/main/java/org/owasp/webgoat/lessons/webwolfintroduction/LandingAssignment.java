/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class LandingAssignment implements AssignmentEndpoint {
  private final String landingPageUrl;

  public LandingAssignment(@Value("${webwolf.landingpage.url}") String landingPageUrl) {
    this.landingPageUrl = landingPageUrl;
  }

  @PostMapping("/WebWolf/landing")
  @ResponseBody
  public AttackResult click(String uniqueCode, @CurrentUsername String username) {
    /*
     * What this used to accept was the caller's own name spelled backwards.
     *
     * That value is not a secret in any sense: it is computable by anybody who knows the account
     * name, this application planted it in the page below so the browser already held it, and
     * following that link carried it in the query string to a host nobody here controls - where it
     * survives in the access log and in the referrer of everything that page loads. A value that
     * travels through all of those places proves nothing about who sent it back, so it is no longer
     * treated as proof of anything.
     */
    return failed(this).feedback("webwolf.landing_wrong").build();
  }

  @GetMapping("/WebWolf/landing/password-reset")
  public ModelAndView openPasswordReset(@CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    modelAndView.addObject(
        "webwolfLandingPageUrl", landingPageUrl.replace("//landing", "/landing"));
    // and it is no longer handed to the browser either
    modelAndView.setViewName("lessons/webwolfintroduction/templates/webwolfPasswordReset.html");
    return modelAndView;
  }
}
