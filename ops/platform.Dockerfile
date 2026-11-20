FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml ./
COPY engine-service/pom.xml engine-service/pom.xml
COPY platform-service/pom.xml platform-service/pom.xml
COPY platform-service/src platform-service/src
RUN mvn -B -pl platform-service -am package -DskipTests

ARG BASE_JRE_IMAGE=eclipse-temurin:21-jre-jammy
FROM ${BASE_JRE_IMAGE}
RUN groupadd --gid 10001 gmssl && useradd --uid 10001 --gid gmssl --create-home gmssl \
    && mkdir -p /app /data/vault && chown 10001:10001 /app /data /data/vault
WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/platform-service/target/platform-service-0.1.0-SNAPSHOT.jar /app/service.jar
USER 10001:10001
ENV SERVER_PORT=8080 GMSSL_VAULT_DIR=/data/vault
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/service.jar"]