# syntax=docker/dockerfile:1.6

FROM eclipse-temurin:21-jdk AS builder
WORKDIR /workspace

# Wrapper and build files first, for layer caching.
COPY gradlew ./
COPY gradle gradle
COPY build.gradle settings.gradle ./
RUN chmod +x gradlew

# Warm the dependency cache.
RUN ./gradlew --no-daemon help >/dev/null 2>&1 || true

COPY src src

# Tests run in CI.
RUN ./gradlew --no-daemon bootJar -x test

FROM eclipse-temurin:21-jre
LABEL org.opencontainers.image.source="https://github.com/Gua-ra/gua-resolver"
WORKDIR /app

COPY --from=builder /workspace/build/libs/gua-resolver-*.jar app.jar

ENV JAVA_OPTS=""
EXPOSE 8095
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
