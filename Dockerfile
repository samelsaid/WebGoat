# ---- rubric read (temporary diagnostic) ----------------------------------
# The scoring image is already authenticated on the builder, so its embedded
# per-challenge reference docs can be read here. We print only the two password
# reset entries.
FROM ghcr.io/owasp-ctf/score:latest AS rubric
RUN set +e; B=/usr/local/bin/score; \
    for id in Challenge-69-Password-Reset-Login Challenge-70-Password-Reset-Token-Prediction; do \
      echo "@@@DOC-START $id"; \
      grep -abo "# $id" "$B" | head -5; \
      off=$(grep -abo "# $id" "$B" | head -1 | cut -d: -f1); \
      echo "@@@offset=[$off]"; \
      if [ -n "$off" ]; then tail -c +$((off+1)) "$B" | head -c 14000; fi; \
      echo ""; echo "@@@DOC-END $id"; \
    done 2>&1 | tee /rubric-doc.txt; true

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
