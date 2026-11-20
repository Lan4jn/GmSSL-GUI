ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy
FROM ${BASE_JRE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 gmssl && useradd --uid 10001 --gid gmssl --create-home gmssl \
    && mkdir -p /app /work && chown -R 10001:10001 /app /work
WORKDIR /app
COPY --chown=10001:10001 artifacts/engine-service-0.1.0-SNAPSHOT.jar /app/service.jar
COPY --chown=10001:10001 artifacts/gmssl-runner /app/gmssl-runner
COPY artifacts/GMSSL-LICENSE /app/GMSSL-LICENSE
RUN chmod 755 /app/gmssl-runner
USER 10001:10001
ENV SERVER_PORT=8081 GMSSL_RUNNER_PATH=/app/gmssl-runner GMSSL_ENGINE_WORK_DIR=/work GMSSL_OPENSSL_PATH=/usr/bin/openssl
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/service.jar"]
