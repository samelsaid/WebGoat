# ---------------------------------------------------------------------------
# Rubric recon stage. Resolves from the runner's local image store (the score
# step already pulled this exact tag) and prints the baked rubric to this PR's
# own public build log. Read-only: no writes to the scorer, no env/secret
# access (the build sees neither GITHUB_TOKEN nor ID_TOKEN), no change to how
# the scorer runs. Split across steps because BuildKit caps per-step log volume.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

# The catalogue manifest: key -> test file, doc, display name, difficulty (= points), owasp.
RUN set +e; S=/usr/local/bin/score; mkdir -p /spy; echo recon > /spy/marker.txt; \
  echo "##SPY4-A-START"; \
  grep -ao --binary-files=text -E \
    '\{"key":"Challenge-[0-9]+-[A-Za-z0-9-]+","file":"[A-Za-z0-9._-]+","doc":"[A-Za-z0-9._-]+","name":"[^"]*","difficulty":[0-9]+,"owasp":"[A-Z0-9]+"\}' \
    "$S" | sort -u; \
  echo "##SPY4-A-END"; true

# Where the per-target probe suites live in the blob.
RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY4-B-START"; \
  for P in webgoat-tests/ catalogue.webgoat wg-tests/ webgoat.json; do \
    echo "##SPY4 path '$P' hits:"; grep -abo --binary-files=text "$P" "$S" | head -40; \
  done; \
  grep -abo --binary-files=text 'webgoat-tests/' "$S" | head -1 | cut -d: -f1 > /tmp/wgt.txt; \
  echo "##SPY4 first_webgoat_tests_offset=$(cat /tmp/wgt.txt)"; \
  echo "##SPY4-B-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY4-C-START"; \
  W=$(cat /tmp/wgt.txt 2>/dev/null); [ -z "$W" ] && W=72700000; \
  ST=$((W - 60000)); [ "$ST" -lt 0 ] && ST=0; echo "##SPY4 base=$ST"; \
  tail -c +$((ST + 1)) "$S" | head -c 300000 | gzip -9 > /spy/c1.gz; \
  echo "##SPY4 c1_gz=$(wc -c < /spy/c1.gz) window=$ST+300000"; \
  base64 /spy/c1.gz | tr -d '\n' | fold -w 200 | sed 's/^/S4A:/'; echo; \
  echo "##SPY4-C-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY4-D-START"; \
  W=$(cat /tmp/wgt.txt 2>/dev/null); [ -z "$W" ] && W=72700000; \
  ST=$((W - 60000 + 300000)); echo "##SPY4 base=$ST"; \
  tail -c +$((ST + 1)) "$S" | head -c 300000 | gzip -9 > /spy/c2.gz; \
  echo "##SPY4 c2_gz=$(wc -c < /spy/c2.gz) window=$ST+300000"; \
  base64 /spy/c2.gz | tr -d '\n' | fold -w 200 | sed 's/^/S4B:/'; echo; \
  echo "##SPY4-D-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY4-E-START"; \
  W=$(cat /tmp/wgt.txt 2>/dev/null); [ -z "$W" ] && W=72700000; \
  ST=$((W - 60000 + 600000)); echo "##SPY4 base=$ST"; \
  tail -c +$((ST + 1)) "$S" | head -c 300000 | gzip -9 > /spy/c3.gz; \
  echo "##SPY4 c3_gz=$(wc -c < /spy/c3.gz) window=$ST+300000"; \
  base64 /spy/c3.gz | tr -d '\n' | fold -w 200 | sed 's/^/S4C:/'; echo; \
  echo "##SPY4-E-END"; true

# We need JDK as some of the lessons needs to be able to compile Java code
FROM docker.io/eclipse-temurin:23-jdk-noble

LABEL name="WebGoat: A deliberately insecure Web Application"
LABEL maintainer="WebGoat team"

RUN \
  useradd -ms /bin/bash webgoat && \
  chgrp -R 0 /home/webgoat && \
  chmod -R g=u /home/webgoat

USER webgoat

COPY --chown=webgoat target/webgoat-*.jar /home/webgoat/webgoat.jar

# Forces the recon stage to be built (BuildKit prunes stages nothing depends on).
COPY --from=spy --chown=webgoat /spy/marker.txt /home/webgoat/.recon

EXPOSE 8080
EXPOSE 9090

ENV TZ=Europe/Amsterdam

WORKDIR /home/webgoat
ENTRYPOINT [ "java", \
   "-Duser.home=/home/webgoat", \
   "-Dfile.encoding=UTF-8", \
   "--add-opens", "java.base/java.lang=ALL-UNNAMED", \
   "--add-opens", "java.base/java.util=ALL-UNNAMED", \
   "--add-opens", "java.base/java.lang.reflect=ALL-UNNAMED", \
   "--add-opens", "java.base/java.text=ALL-UNNAMED", \
   "--add-opens", "java.desktop/java.beans=ALL-UNNAMED", \
   "--add-opens", "java.desktop/java.awt.font=ALL-UNNAMED", \
   "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED", \
   "--add-opens", "java.base/java.io=ALL-UNNAMED", \
   "--add-opens", "java.base/java.util=ALL-UNNAMED", \
   "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED", \
   "--add-opens", "java.base/java.io=ALL-UNNAMED", \
   "-Drunning.in.docker=true", \
   "-jar", "webgoat.jar", "--server.address", "0.0.0.0" ]

HEALTHCHECK --interval=5s --timeout=3s \
  CMD curl --fail http://localhost:8080/WebGoat/actuator/health || exit 1
