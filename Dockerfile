# Etapa de construcción (usa Maven para compilar el proyecto)
FROM maven:3.9.4-eclipse-temurin-17 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# Etapa final (imagen más liviana con sólo el .jar ejecutable)
FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app

# Copia el JAR compilado desde la imagen anterior
COPY --from=build /app/target/*.jar app.jar

# Expone el puerto que configuraste (8081 por defecto)
EXPOSE 8081

# Ejecuta tu aplicación
ENTRYPOINT ["java", "-jar", "app.jar"]