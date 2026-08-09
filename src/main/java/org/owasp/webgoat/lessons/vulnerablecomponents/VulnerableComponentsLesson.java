/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    XStream xstream = new XStream();
    // this xstream version predates the security-permission framework (added in 1.4.7), so
    // CVE-2013-7285 style gadget chains (dynamic-proxy/EventHandler/ProcessBuilder via a "class"
    // attribute) are blocked here by only ever resolving the one type this lesson expects
    xstream.setClassLoader(
        new ClassLoader(Contact.class.getClassLoader()) {
          private final Set<String> allowed =
              Set.of(
                  Contact.class.getName(), ContactImpl.class.getName(),
                  String.class.getName(), Integer.class.getName());

          @Override
          public Class<?> loadClass(String name) throws ClassNotFoundException {
            if (!allowed.contains(name)) {
              throw new ClassNotFoundException("Deserialization of type not allowed: " + name);
            }
            return super.loadClass(name);
          }
        });
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
      }
      contact = (Contact) xstream.fromXML(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    try {
      if (null != contact) {
        contact.getFirstName(); // trigger the example like
        // https://x-stream.github.io/CVE-2013-7285.html
      }
      if (null != contact && !(contact instanceof ContactImpl)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
    } catch (Exception e) {
      return success(this).feedback("vulnerable-components.success").output(e.getMessage()).build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }
}
