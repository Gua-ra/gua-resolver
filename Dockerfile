# syntax=docker/dockerfile:1.6

##############################
# Build stage
##############################
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /workspace

# Copy Gradle wrapper and build files first for better layer caching
COPY gradlew gradlew*
COPY gradle gradle
COPY build.gradle settings.gradle .

# Warm up dependency cache (ignore failure if the task isn't available)
RUN ./gradlew --no-daemon help >/dev/null 2>&1 || true

# Copy source
COPY src src

# Build the fat jar (tests run in CI)
RUN ./gradlew --no-daemon bootJar -x test

##############################
# Runtime stage
##############################
FROM eclipse-temurin:21-jre
LABEL org.opencontainers.image.source="https://github.com/Gua-ra/gua-resolver"
WORKDIR /app

COPY --from=builder /workspace/build/libs/gua-resolver-*.jar app.jar

ENV JAVA_OPTS=""
EXPOSE 8095
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
