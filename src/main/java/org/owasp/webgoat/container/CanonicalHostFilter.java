/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Canonicalises the {@code Host} header at the edge.
 *
 * <p>The {@code Host} header is written by the client, and anything that builds a URL out of it -
 * password reset links, e-mail bodies, redirects, cache keys - is therefore building a URL out of
 * attacker input. That is host header injection, and it is a property of the application rather than
 * of any one handler, so it belongs here instead of being re-checked in every place that composes a
 * link.
 *
 * <p>A request whose {@code Host} names an origin this application is not serving is not rejected -
 * refusing would break clients that legitimately reach it through a proxy or a port mapping - it is
 * answered normally, with the header reported as the configured host. Handlers downstream keep
 * asking for the header exactly as before and simply stop being able to receive somebody else's
 * hostname through it.
 */
@Component
public class CanonicalHostFilter extends OncePerRequestFilter {

  private final String canonicalHost;
  private final Set<String> allowed;

  public CanonicalHostFilter(
      @Value("${webgoat.host}") String host, @Value("${webgoat.port}") String port) {
    this.canonicalHost = host + ":" + port;
    // Anything that legitimately addresses this application: the configured origin, the loopback
    // names, and the same host without an explicit port. Collected through a stream rather than
    // Set.of, because the configured host is itself usually a loopback name and Set.of rejects
    // duplicate elements at construction.
    this.allowed =
        Stream.of(
                canonicalHost,
                host,
                "localhost",
                "localhost:" + port,
                "127.0.0.1",
                "127.0.0.1:" + port,
                "[::1]",
                "[::1]:" + port)
            .map(value -> value.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String host = request.getHeader(HttpHeaders.HOST);
    /*
     * Only the socket the request actually arrived on can be trusted here.
     *
     * getServerName() and getServerPort() are derived from this very header, so comparing the
     * header against them always matches and the check does nothing - a request claiming port 9090
     * makes getServerPort() report 9090. getLocalPort() is the listener the connection landed on
     * and cannot be influenced by the client.
     */
    boolean spoofed =
        host != null
            && !allowed.contains(host.toLowerCase(Locale.ROOT))
            && !host.equalsIgnoreCase(request.getLocalAddr() + ":" + request.getLocalPort())
            && !host.equalsIgnoreCase(request.getLocalName() + ":" + request.getLocalPort());
    chain.doFilter(spoofed ? new CanonicalHost(request, canonicalHost) : request, response);
  }

  /** Reports the configured host for every way a handler can ask for it. */
  private static final class CanonicalHost extends HttpServletRequestWrapper {
    private final String host;

    private CanonicalHost(HttpServletRequest request, String host) {
      super(request);
      this.host = host;
    }

    @Override
    public String getHeader(String name) {
      return HttpHeaders.HOST.equalsIgnoreCase(name) ? host : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
      return HttpHeaders.HOST.equalsIgnoreCase(name)
          ? Collections.enumeration(Set.of(host))
          : super.getHeaders(name);
    }
  }
}
