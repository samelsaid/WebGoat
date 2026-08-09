/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicBoolean;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {
  private static final String DEFAULT_PASSWORD = "passW0rD";
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final AtomicBoolean SHIPPED_PASSWORD_ROTATED = new AtomicBoolean(false);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    String currentPassword = getPassword();
    if (!DEFAULT_PASSWORD.equals(currentPassword) && userid_6b.equals(currentPassword)) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  protected String getPassword() {
    // random fallback: a database error must not leave a known value behind
    String password = randomPassword();
    try (Connection connection = dataSource.getConnection()) {
      rotateShippedPassword(connection);
      String query = "SELECT password FROM user_system_data WHERE user_name = 'dave'";
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results != null && results.first()) {
          password = results.getString("password");
        }
      } catch (SQLException sqle) {
        sqle.printStackTrace();
        // do nothing
      }
    } catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
    return (password);
  }

  /**
   * The seed data carries a plaintext password that the lesson prints, so it is replaced by a
   * random one the first time it is read. Doing that on every read instead re-drew the password
   * inside the same call that then compared it, so the value being checked had already been thrown
   * away and no answer could ever match; it also turned every attempt at this assignment into a
   * database write.
   */
  private void rotateShippedPassword(Connection connection) {
    if (!SHIPPED_PASSWORD_ROTATED.compareAndSet(false, true)) {
      return;
    }
    try (PreparedStatement statement =
        connection.prepareStatement(
            "UPDATE user_system_data SET password = ? WHERE user_name = ?")) {
      statement.setString(1, randomPassword());
      statement.setString(2, "dave");
      statement.executeUpdate();
    } catch (SQLException sqle) {
      // leave the stored value alone, and allow a later attempt to try the rotation again
      SHIPPED_PASSWORD_ROTATED.set(false);
    }
  }

  // eight hex characters, which is what the password column holds
  private static String randomPassword() {
    byte[] secret = new byte[4];
    RANDOM.nextBytes(secret);
    return HexFormat.of().formatHex(secret);
  }
}
