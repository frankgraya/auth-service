# auth-service


# 🔐 Auth Service - Microservicio de Autenticación

Este servicio es la puerta de entrada a tu arquitectura de microservicios. Provee autenticación mediante credenciales de usuario y emite tokens JWT seguros para proteger tus APIs.

---

## 📌 Funcionalidades

- ✅ Registro de usuarios
- ✅ Inicio de sesión con JWT
- ✅ Validación de tokens
- ✅ Roles y seguridad básica
- ✅ Integración con Eureka (descubrimiento de servicios)
- ✅ Compatible con Spring Cloud Gateway

---

## 🛠️ Tecnologías

- Java 17
- Spring Boot
- Spring Security + JWT
- Spring Data JPA
- PostgreSQL
- Eureka Client
- Docker / Docker Compose

---

## 📁 Estructura del Proyecto

```
auth-service/
├── controller/         # Controladores REST (login, registro)
├── model/              # Entidades y DTOs
├── repository/         # Repositorio JPA
├── security/           # JWT, filtros y configuración
├── service/            # Lógica de autenticación
└── AuthServiceApp.java # Main Application
```

---

## ⚙️ Configuración (application.yml)

```yaml
server:
  port: 8081

spring:
  datasource:
    url: jdbc:postgresql://db:55432/authdb
    username: authuser
    password: authpass
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka
```

---

## 🐳 Docker

### 📄 Dockerfile

```dockerfile
FROM openjdk:17-jdk-slim
VOLUME /tmp
COPY target/auth-service.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
```

### 🧱 docker-compose.yml

```yaml
version: '3.8'

services:
  auth-service:
    build: .
    container_name: auth-service
    ports:
      - "8081:8081"
    environment:
      SPRING_DATASOURCE_URL: jdbc:postgresql://db:55432/authdb
      SPRING_DATASOURCE_USERNAME: authuser
      SPRING_DATASOURCE_PASSWORD: authpass
    depends_on:
      - db
      - eureka

  db:
    image: postgres:15
    container_name: postgres-auth
    environment:
      POSTGRES_DB: authdb
      POSTGRES_USER: authuser
      POSTGRES_PASSWORD: authpass
    ports:
      - "55432:5432"

  eureka:
    image: eurekaserver:latest
    container_name: eureka
    ports:
      - "8761:8761"
```

### ▶️ Comando para ejecutar

```bash
docker-compose up --build
```

---

## 🔑 Endpoints principales

| Método | Endpoint         | Función                  |
|--------|------------------|--------------------------|
| POST   | `/auth/register` | Registro de usuario      |
| POST   | `/auth/login`    | Login y generación de JWT|

---

## 📣 Notas

- Este servicio **no incluye refresh tokens** por defecto.
- La contraseña se encripta con `BCryptPasswordEncoder`.
- JWT se firma con una clave secreta configurable en el `application.yml`.

---

## 👨‍💻 Autor

**Frank Graya**  
📧 francisco.graya26@gmail.com
🚀 Proyecto en arquitectura de microservicios con Spring Cloud

---

> “El primer paso para proteger tu sistema es un buen sistema de autenticación.”
