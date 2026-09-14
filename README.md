# DigitalFix - ms-login

Microservicio de autenticación y auditoría de accesos del sistema **DigitalFix**, una plataforma de órdenes de trabajo de mantención eléctrica. Construido con **Spring Boot** y **Spring Security OAuth2 Resource Server**, valida los JWT emitidos por **Microsoft Entra ID (Azure AD)** y registra cada intento de inicio de sesión en una base de datos **Oracle**.

Dentro de la arquitectura de DigitalFix, este servicio se ubica detrás del flujo `JWT -> API Gateway -> ms-digitalfix-bff -> microservicio de dominio`, actuando como el punto que confirma la autenticación del usuario y deja constancia (auditoría) de cada acceso.

---

## Propósito del microservicio

- Filtrar la autenticación del usuario validando el JWT emitido por Azure AD.
- Controlar el acceso al sistema exponiendo un endpoint de verificación de estado de sesión.
- Registrar en base de datos los intentos de inicio de sesión (éxito, fallo o cuenta bloqueada) para trazabilidad y auditoría.

---

## Stack tecnológico

- **Framework**: Spring Boot (spring-boot-starter-parent 4.0.8)
- **Lenguaje**: Java 21
- **Seguridad**: Spring Security + OAuth2 Resource Server (validación de JWT de Microsoft Entra ID vía `spring-cloud-azure-starter`)
- **Persistencia**: Spring Data JPA + Oracle Database (driver `ojdbc17`)
- **Migraciones de base de datos**: Flyway (`flyway-database-oracle`)
- **Documentación de API**: springdoc-openapi (Swagger UI)
- **Utilitarios**: Lombok
- **Build**: Maven (con Maven Wrapper)

---

## Requisitos

- JDK 21
- Maven (o usar el wrapper `mvnw` / `mvnw.cmd` incluido en el proyecto)
- Una base de datos Oracle accesible (local, en contenedor o en la nube)
- Un App Registration en Microsoft Entra ID (tenant ID y client ID)
- Docker (opcional, para ejecutar el servicio y la base de datos en contenedores)

---

## Configuración

El servicio se configura mediante variables de entorno, definidas en [`src/main/resources/application.yaml`](src/main/resources/application.yaml):

| Variable | Descripción | Ejemplo |
|---|---|---|
| `SPRING_DATASOURCE_URL` | URL JDBC de la base de datos Oracle | `jdbc:oracle:thin:@//oracle-db:1521/FREEPDB1` |
| `SPRING_DATASOURCE_USERNAME` | Usuario de la base de datos | `system` |
| `SPRING_DATASOURCE_PASSWORD` | Contraseña de la base de datos | `system` |
| `AZURE_TENANT_ID` | Tenant ID del App Registration en Microsoft Entra ID | `2845a269-a60f-4fdf-969c-2811937a2e85` |
| `AZURE_CLIENT_ID` | Client ID del App Registration, usado para validar la audiencia (`aud`) del JWT | `9494b59c-9c6e-4a0f-91ae-ae90212882e7` |

A partir de `AZURE_TENANT_ID`, el servicio calcula automáticamente el emisor esperado del token:

```
issuer-uri: https://login.microsoftonline.com/${AZURE_TENANT_ID}/v2.0
audiences: api://${AZURE_CLIENT_ID}
```

Nota: `AZURE_CLIENT_ID` tiene un valor de respaldo definido en [`SecurityConfig`](src/main/java/df/digitalfix_ms_login/config/SecurityConfig.java) únicamente para entornos de desarrollo; en cualquier despliegue real debe fijarse explícitamente al Client ID correcto.

---

## Quick start (desarrollo local)

1. Levantar una base de datos Oracle accesible y exportar las variables de entorno de conexión y de Azure AD:

```bash
export SPRING_DATASOURCE_URL=jdbc:oracle:thin:@//localhost:1521/FREEPDB1
export SPRING_DATASOURCE_USERNAME=system
export SPRING_DATASOURCE_PASSWORD=system
export AZURE_TENANT_ID=<AZURE_TENANT_ID>
export AZURE_CLIENT_ID=<AZURE_CLIENT_ID>
```

2. Ejecutar el servicio con el Maven Wrapper:

```bash
./mvnw spring-boot:run
```

El servicio queda disponible en `http://localhost:8080`. Al iniciar, Flyway aplica las migraciones ubicadas en `src/main/resources/db/migration`.

### Compilar y empaquetar

```bash
./mvnw clean package
```

El artefacto `.jar` queda generado en `target/`.

### Ejecutar pruebas

```bash
./mvnw test
```

---

## Seguridad

La configuración de seguridad vive en [`SecurityConfig`](src/main/java/df/digitalfix_ms_login/config/SecurityConfig.java):

- El servicio funciona como **OAuth2 Resource Server**: toda petición debe incluir un JWT válido emitido por Microsoft Entra ID, excepto los endpoints de documentación (`/v3/api-docs/**`, `/swagger-ui/**`, `/swagger-ui.html`), que son públicos.
- El `JwtDecoder` valida:
  - El **issuer**, contra `https://login.microsoftonline.com/<AZURE_TENANT_ID>/v2.0`.
  - La **audiencia** (`aud`), que debe coincidir con `AZURE_CLIENT_ID` o con `api://<AZURE_CLIENT_ID>`, tanto si el claim viene como texto simple o como lista.
- La sesión es **stateless** (`SessionCreationPolicy.STATELESS`) y CSRF está deshabilitado, ya que el servicio no mantiene sesión de servidor y toda la autenticación viaja en el token de cada petición.
- Con `@EnableMethodSecurity` se habilita autorización a nivel de método: el endpoint de estado de login exige el scope `SCP_Auth.Access` mediante `@PreAuthorize`.

---

## Endpoints

| Método | Ruta | Protección | Descripción |
|---|---|---|---|
| GET | `/api/v1/login/status` | JWT válido + scope `SCP_Auth.Access` | Confirma que la autenticación contra Azure AD fue exitosa. |
| POST | `/api/v1/audit/login` | JWT válido (cualquier usuario autenticado) | Registra un intento de inicio de sesión (éxito, fallo o cuenta bloqueada). |
| GET | `/v3/api-docs`, `/swagger-ui/**`, `/swagger-ui.html` | Público | Documentación OpenAPI / Swagger UI. |

### POST /api/v1/audit/login

Cuerpo de la petición ([`LoginAuditRequest`](src/main/java/df/digitalfix_ms_login/dto/LoginAuditRequest.java)):

```json
{
  "username": "usuario@dominio.com",
  "success": false,
  "ipAddress": "192.168.1.10",
  "userAgent": "Mozilla/5.0",
  "failureReason": "Cuenta bloqueada"
}
```

- `username`, `success` e `ipAddress` son obligatorios; `userAgent` y `failureReason` son opcionales.
- El tipo de evento se resuelve automáticamente en el servicio: `LOGIN_SUCCESS` si `success` es verdadero, `ACCOUNT_BLOCKED` si `failureReason` contiene la palabra "bloqueada", o `LOGIN_FAILURE` en cualquier otro caso de fallo.
- Respuesta exitosa: `201 Created` sin cuerpo.
- Si la validación de datos falla, responde `400 Bad Request` con el siguiente formato ([`ErrorResponse`](src/main/java/df/digitalfix_ms_login/dto/ErrorResponse.java)):

```json
{
  "status": 400,
  "message": "Error de validacion de los datos",
  "timestamp": "2026-09-13T10:00:00",
  "errors": ["El nombre de usuario es obligatorio"]
}
```

---

## Base de datos

El esquema se gestiona con Flyway. La migración inicial [`V1__crear_tabla_auditoria_login.sql`](src/main/resources/db/migration/V1__crear_tabla_auditoria_login.sql) crea la tabla `LOG_AUDITORIA_ACCESO`:

| Columna | Tipo | Descripción |
|---|---|---|
| `ID` | `NUMBER(19,0)` | Identidad autogenerada, llave primaria. |
| `USER_ENTRA_ID` | `VARCHAR2(100)` | Identificador del usuario en Microsoft Entra ID. |
| `EVENTO` | `VARCHAR2(50)` | Tipo de evento (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCOUNT_BLOCKED`). |
| `DIRECCION_IP` | `VARCHAR2(45)` | Dirección IP de origen del intento. |
| `USER_AGENT` | `VARCHAR2(500)` | Cliente o navegador desde el que se realizó el intento. |
| `FECHA_REGISTRO` | `TIMESTAMP` | Fecha y hora de registro del evento. |

Existe además un índice `IDX_AUDITORIA_USER` sobre `USER_ENTRA_ID` para acelerar las búsquedas por usuario.

Nota: la entidad [`LoginAudit`](src/main/java/df/digitalfix_ms_login/entity/LoginAudit.java) agrega también la columna `MOTIVO_FALLO`, no incluida en la migración inicial de Flyway; se sincroniza automáticamente gracias a `spring.jpa.hibernate.ddl-auto: update`, configurado en `application.yaml` como complemento a Flyway.

---

## Dockerización

El proyecto incluye un `Dockerfile` multi-stage y un `docker-compose.yaml` para levantar el servicio junto a una base de datos Oracle de prueba.

### Detalle del Dockerfile

- **Etapa `builder`**: imagen `maven:3.9.8-eclipse-temurin-21-alpine`, resuelve dependencias (`mvn dependency:go-offline`) y compila el proyecto (`mvn package -DskipTests`).
- **Etapa final**: imagen liviana `eclipse-temurin:21-jre-alpine`, ejecuta la aplicación con un usuario no root (`spring:spring`) y expone el puerto `8080`.

### Build y ejecución con Docker

```bash
docker build -t digitalfix-ms-login .
docker run --rm -p 8080:8080 \
  -e SPRING_DATASOURCE_URL=jdbc:oracle:thin:@//<host>:1521/FREEPDB1 \
  -e SPRING_DATASOURCE_USERNAME=system \
  -e SPRING_DATASOURCE_PASSWORD=system \
  -e AZURE_TENANT_ID=<AZURE_TENANT_ID> \
  -e AZURE_CLIENT_ID=<AZURE_CLIENT_ID> \
  --name digitalfix-ms-login digitalfix-ms-login
```

### Con Docker Compose

El `docker-compose.yaml` levanta dos servicios:

- `oracle-db`: base de datos Oracle Free (`gvenzl/oracle-free:23-slim`), expuesta en el puerto `1521`, con volumen persistente `oracle_data`.
- `ms-login`: construye la imagen del microservicio a partir del `Dockerfile`, expuesta en el puerto `8080`, y espera a que `oracle-db` esté saludable antes de iniciar.

```bash
export AZURE_TENANT_ID=<AZURE_TENANT_ID>
docker compose up --build
```

Para detenerlo:

```bash
docker compose down
```

Nota: las credenciales de la base de datos y `AZURE_CLIENT_ID` quedan fijadas en el propio `docker-compose.yaml` para fines de prueba local; deben reemplazarse por variables de entorno o un gestor de secretos antes de cualquier despliegue real.

---

## Estructura del proyecto

```text
digitalfix-ms-login/
├── Dockerfile
├── docker-compose.yaml
├── pom.xml
├── mvnw / mvnw.cmd
└── src/
    ├── main/
    │   ├── java/df/digitalfix_ms_login/
    │   │   ├── config/       # Configuración de seguridad (JWT de Azure AD)
    │   │   ├── controller/   # Endpoints REST (login, auditoría)
    │   │   ├── dto/          # Objetos de transferencia (request/response)
    │   │   ├── entity/       # Entidades JPA
    │   │   ├── enums/        # Tipos de evento de auditoría
    │   │   ├── exception/    # Manejo global de excepciones
    │   │   ├── repository/   # Repositorios JPA
    │   │   ├── service/      # Lógica de negocio
    │   │   └── DigitalfixMsLoginApplication.java
    │   └── resources/
    │       ├── application.yaml
    │       └── db/migration/ # Scripts de Flyway
    └── test/
        └── java/df/digitalfix_ms_login/
```

---

## Comandos disponibles

```bash
./mvnw spring-boot:run       # ejecutar el servicio en modo desarrollo
./mvnw clean package         # compilar y generar el jar (con pruebas)
./mvnw clean package -DskipTests  # generar el jar sin ejecutar pruebas
./mvnw test                  # ejecutar las pruebas
```
