/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.math.BigDecimal;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  private static final BigDecimal PRICE = new BigDecimal("2999.99");

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    // price is authoritative server-side; a client-supplied total is never trusted
    try {
      BigDecimal qty = new BigDecimal(QTY);
      BigDecimal total = new BigDecimal(Total);
      if (qty.signum() <= 0 || PRICE.multiply(qty).compareTo(total) != 0) {
        return failed(this).feedback("html-tampering.tamper.failure").build();
      }
      return success(this).feedback("html-tampering.tamper.success").build();
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
  }
}
