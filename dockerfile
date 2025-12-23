FROM eclipse-temurin:17-jre
WORKDIR /app
COPY target/trivy-automation-demo-0.0.1-SNAPSHOT.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]