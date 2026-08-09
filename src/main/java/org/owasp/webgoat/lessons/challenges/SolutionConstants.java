/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.util.UUID;

public interface SolutionConstants {

  /**
   * Where the challenge substitutes its pincode. It is spelled with characters that cannot occur in
   * the random hex below, so the substitution can only ever hit this one spot. A digit run such as
   * "1234" could also appear inside the random part, and replacing every occurrence of it would
   * then corrupt the credential.
   */
  String PINCODE_PLACEHOLDER = "{pincode}";

  /**
   * A credential written into the source is public: it sits in the repository, in every build and
   * in every container image. The unguessable part is drawn once per run instead, and the pincode
   * the challenge fills in is itself random.
   */
  String PASSWORD =
      "!!webgoat_admin_"
          + UUID.randomUUID().toString().replace("-", "")
          + "_"
          + PINCODE_PLACEHOLDER
          + "!!";
}
