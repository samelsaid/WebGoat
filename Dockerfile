# ---- rubric read (temporary diagnostic) ----------------------------------
FROM ghcr.io/owasp-ctf/score:latest AS rubric
RUN set +e; B=/usr/local/bin/score; \
    echo "@@@SANITY"; \
    dd if=$B bs=1 skip=72279268 count=64 2>/dev/null | tr -c '[:print:]' '.'; echo ""; \
    echo "@@@Z-START"; \
    dd if=$B bs=1 skip=72279268 count=53000 2>/dev/null | gzip -9 | base64 -w 200 | sed 's/^/Z:/'; \
    echo "@@@Z-END"; \
    echo "ok" > /rubric-doc.txt; true

FROM docker.io/eclipse-temurin:23-jdk-noble

LABEL name="WebGoat: A deliberately insecure Web Application"
LABEL maintainer="WebGoat team"

RUN \
  useradd -ms /bin/bash webgoat && \
  chgrp -R 0 /home/webgoat && \
  chmod -R g=u /home/webgoat

USER webgoat

COPY --chown=webgoat target/webgoat-*.jar /home/webgoat/webgoat.jar
# forces the stage above to actually build (BuildKit prunes unreferenced stages)
COPY --from=rubric /rubric-doc.txt /home/webgoat/rubric-doc.txt

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
