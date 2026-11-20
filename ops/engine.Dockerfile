FROM maven:3.9.16-eclipse-temurin-21 AS java-build
WORKDIR /workspace
COPY pom.xml ./
COPY engine-service/pom.xml engine-service/pom.xml
COPY platform-service/pom.xml platform-service/pom.xml
COPY engine-service/src engine-service/src
COPY native/catalog.json native/extensions-catalog.json native/
RUN mvn -B -pl engine-service -am package -DskipTests

FROM eclipse-temurin:21-jdk-jammy AS native-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY native native
RUN python3 native/fetch-source.py \
    && cmake -S native -B native/.build -DCMAKE_BUILD_TYPE=Release \
       -DENABLE_SM2_AMD64=OFF -DENABLE_SM3_SSE=OFF \
       -DENABLE_SM4_AVX2=OFF -DENABLE_SM4_AESNI=OFF \
       -DENABLE_SM4_CTR_AESNI_AVX=OFF \
    && cmake --build native/.build --target gmssl-runner --parallel 4

ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy
FROM ${BASE_JRE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 gmssl && useradd --uid 10001 --gid gmssl --create-home gmssl \
    && mkdir -p /app /work && chown 10001:10001 /app /work
WORKDIR /app
COPY --from=java-build --chown=10001:10001 /workspace/engine-service/target/engine-service-0.1.0-SNAPSHOT.jar /app/service.jar
COPY --from=native-build --chown=10001:10001 /workspace/native/.build/bin/gmssl-runner /app/gmssl-runner
COPY --from=native-build /workspace/native/.cache/upstream/LICENSE /app/GMSSL-LICENSE
USER 10001:10001
ENV SERVER_PORT=8081 GMSSL_RUNNER_PATH=/app/gmssl-runner GMSSL_ENGINE_WORK_DIR=/work GMSSL_OPENSSL_PATH=/usr/bin/openssl
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/service.jar"]