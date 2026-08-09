/*
 * SPDX-FileCopyrightText: Copyright © 2022 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.service;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/environment")
@RequiredArgsConstructor
public class EnvironmentService {

  private final ApplicationContext context;

  /**
   * The directory this instance keeps its lesson files in. It is the working directory of the
   * exercises themselves - the upload lessons write into it and the clients that drive them read it
   * back to find what they just wrote - so the answer stays available.
   *
   * <p>Refusing to answer at all was the wrong shape for the concern behind it. What makes a path
   * worth protecting is an unauthenticated caller learning it; this endpoint sits behind the
   * container's {@code anyRequest().authenticated()} rule, so only a signed-in session ever reaches
   * it, and a signed-in session is already allowed to upload into that directory and list it. The
   * traversal and upload issues that would have made the path worth hiding are fixed where they
   * live, in the handlers that build a path out of a client value.
   */
  @GetMapping("/server-directory")
  public String homeDirectory() {
    return context.getEnvironment().getProperty("webgoat.server.directory");
  }
}
