/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
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
      "SqlOnlyInputValidationOnKeywords-1",
      "SqlOnlyInputValidationOnKeywords-2",
      "SqlOnlyInputValidationOnKeywords-3"
    })
public class SqlOnlyInputValidationOnKeywords implements AssignmentEndpoint {

  private static final String QUERY = "SELECT * FROM user_data WHERE last_name = ?";

  /**
   * What this field genuinely is: a surname. Anything outside a plain name is turned away at the
   * boundary rather than scrubbed and then used, so an injection payload never reaches the query
   * at all. Quotes, spaces, tabs, comment markers and semicolons are all excluded by construction.
   */
  private static final Pattern LAST_NAME = Pattern.compile("[A-Za-z][A-Za-z'-]{0,49}");

  private final LessonDataSource dataSource;

  public SqlOnlyInputValidationOnKeywords(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlOnlyInputValidationOnKeywords/attack")
  @ResponseBody
  public AttackResult attack(
      @RequestParam("userid_sql_only_input_validation_on_keywords") String userId) {
    /*
     * The keyword scrub that used to stand here did damage in both directions. It was no defence:
     * stripping FROM and SELECT leaves every other way of writing an injection intact. And it was
     * lossy in a way that broke the lesson outright - it upper-cased the value before binding it,
     * while last_name holds mixed-case surnames and the comparison is case sensitive, so no
     * legitimate surname could ever match and the query answered "no results" to everything.
     *
     * Scrubbing is replaced by refusing: the value is checked against what a surname actually
     * looks like, and the value that was checked is the value that gets bound.
     */
    if (userId == null || !LAST_NAME.matcher(userId).matches()) {
      return failed(this).feedback("SqlOnlyInputValidationOnKeywords-failed").build();
    }
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(QUERY)) {
      statement.setString(1, userId);
      try (ResultSet results = statement.executeQuery()) {
        return failed(this).output(renderResults(results)).build();
      }
    } catch (SQLException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private String renderResults(ResultSet results) throws SQLException {
    ResultSetMetaData metaData = results.getMetaData();
    int numberOfColumns = metaData.getColumnCount();
    StringBuilder table = new StringBuilder("<p>");
    boolean headerWritten = false;

    while (results.next()) {
      if (!headerWritten) {
        for (int i = 1; i < (numberOfColumns + 1); i++) {
          table.append(metaData.getColumnName(i));
          table.append(", ");
        }
        table.append("<br />");
        headerWritten = true;
      }
      for (int i = 1; i < (numberOfColumns + 1); i++) {
        table.append(results.getString(i));
        table.append(", ");
      }
      table.append("<br />");
    }

    if (!headerWritten) {
      table.append("No results matched. Try Again.");
    }
    table.append("</p>");
    return table.toString();
  }
}
