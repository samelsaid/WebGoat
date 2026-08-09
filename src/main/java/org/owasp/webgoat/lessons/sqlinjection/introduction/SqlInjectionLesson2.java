/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private static final String REFUSED =
      "Only a single SELECT is run here. Anything that would change data, change the schema or"
          + " change a privilege is refused.";

  /**
   * What this endpoint genuinely accepts: one SELECT, and nothing after it.
   *
   * <p>Refusing to run anything at all closed the hole by removing the exercise: reading a table
   * with a query is the whole of this lesson, and the reader was left with an endpoint that
   * answered every query, including the one the instructions ask for, the same way. Running whatever
   * arrives is the other extreme - a statement that updates rows, drops a table or grants a right is
   * not a query and has no business here.
   *
   * <p>So the statement is required to be a single SELECT before it goes anywhere near the database,
   * and it is run on a read-only, non-updatable cursor. A trailing statement is refused rather than
   * stripped, because the value that was checked has to be the value that runs.
   */
  private static final Pattern SINGLE_SELECT =
      Pattern.compile("\\s*select\\s+[^;]*;?\\s*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (query == null || !SINGLE_SELECT.matcher(query).matches()) {
      return failed(this).feedback("sql-injection.2.failed").output(REFUSED).build();
    }
    try (var connection = dataSource.getConnection();
        Statement statement = connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
      ResultSet results = statement.executeQuery(query);
      if (!results.first()) {
        return failed(this).feedback("sql-injection.2.failed").output("").build();
      }
      StringBuilder output = new StringBuilder();
      if ("Marketing".equals(results.getString("department"))) {
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      }
      output.append(SqlInjectionLesson8.generateTable(results));
      return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
    } catch (SQLException e) {
      return failed(this).feedback("sql-injection.2.failed").output(e.getMessage()).build();
    }
  }
}
