# DigitalFix - ms-login

Microservicio de autenticación y auditoría de accesos del sistema **DigitalFix**, una plataforma de órdenes de trabajo de mantención eléctrica. Construido con **Spring Boot** y **Spring Security OAuth2 Resource Server**, valida los JWT emitidos por **Microsoft Entra ID (Azure AD)** y registra cada intento de inicio de sesión en una base de datos **Oracle Autonomous Database (Serverless en Oracle Cloud - OCI)** mediante conexión segura con **Wallet mTLS**.

Dentro de la arquitectura de DigitalFix, este servicio se ubica detrás del flujo `JWT -> API Gateway (AWS) -> ms-digitalfix-bff -> microservicio de dominio`, actuando como el punto que confirma la autenticación del usuario y deja constancia (auditoría) de cada acceso.

---

## Propósito del microservicio

- Filtrar la autenticación del usuario validando el JWT emitido por Azure AD.
- Controlar el acceso al sistema exponiendo un endpoint de verificación de estado de sesión.
- Registrar en base de datos los intentos de inicio de sesión (éxito, fallo o cuenta bloqueada) para trazabilidad y auditoría.

---

## Stack tecnológico

- **Framework**: Spring Boot (spring-boot-starter-parent 4.0.8)
- **Lenguaje**: Java 21
- **Puerto por defecto**: `8081` (configurable mediante variable `PORT`)
- **Seguridad**: Spring Security + OAuth2 Resource Server (validación de JWT de Microsoft Entra ID vía `spring-cloud-azure-starter`)
- **Persistencia**: Spring Data JPA + Oracle Autonomous Database (driver `ojdbc11` + Oracle PKI para mTLS)
- **Migraciones de base de datos**: Flyway (`flyway-database-oracle`)
- **Documentación de API**: springdoc-openapi (Swagger UI)
- **Utilitarios**: Lombok
- **Build**: Maven (con Maven Wrapper)

---

## Requisitos

- JDK 21
- Maven (o usar el wrapper `mvnw` / `mvnw.cmd` incluido en el proyecto)
- Base de datos Oracle Autonomous en OCI con Wallet mTLS descargado
- Un App Registration en Microsoft Entra ID (tenant ID y client ID)
- Docker y Docker Compose (opcional, para ejecutar en contenedor)

---

## Configuración y Variables de Entorno

El microservicio se parametriza mediante variables de entorno en [`src/main/resources/application.yaml`](src/main/resources/application.yaml) o a través de un archivo `.env`:

| Variable | Descripción | Ejemplo Local / Docker |
|---|---|---|
| `PORT` | Puerto HTTP donde escucha el microservicio | `8081` |
| `SPRING_DATASOURCE_URL` | URL JDBC de Oracle Autonomous con ruta a la carpeta del Wallet | `jdbc:oracle:thin:@clx44joct2djmlz9_high?TNS_ADMIN=/app/wallet` |
| `SPRING_DATASOURCE_USERNAME` | Usuario administrador de la base de datos | `ADMIN` |
| `SPRING_DATASOURCE_PASSWORD` | Contraseña del usuario administrador en OCI | `TuPasswordSegura.` |
| `AZURE_TENANT_ID` | Tenant ID del App Registration en Microsoft Entra ID | `3fb8463e-0e33-4b7d-adc1-2a47c707831e` |
| `AZURE_CLIENT_ID` | Client ID del App Registration (audiencia `aud` del JWT) | `9494b59c-9c6e-4a0f-91ae-ae90212882e7` |
| `CORS_ALLOWED_ORIGINS` | Orígenes permitidos para llamadas del navegador (separados por coma) | `http://localhost:4200` |
| `MS_USER_URL` | URL de ms-user, de donde se obtiene el rol de negocio del usuario | `http://localhost:8082` |

**Puerto asignado:** `8081` en desarrollo local, único dentro del ecosistema (ver la [tabla de puertos](https://github.com/SolgreyDuocUC/digitalfix-infrastructure#86-puertos-de-los-microservicios) en `digitalfix-infrastructure`). El `8080` queda libre porque suele estar ocupado por Apache/XAMPP. El `8081` local lo fija `PORT` en el `.env`; sin esa variable se usa el default `8080` de `application.yaml`, que es el que usa la EC2 `ec2-frontend-login` (mapeo `8080:8080`).

> 📖 **Guía paso a paso de Oracle y Wallet:** Para detalles exhaustivos de cómo aprovisionar OCI, descargar el Wallet, evitar el error `ORA-01017` y configurar certificados, consulta [`docs/configuracion-bd.md`](docs/configuracion-bd.md).

### Plantilla de entorno `.env`

Copia el archivo `.env.example` a `.env` (ignorado por git para no subir secretos):

```bash
cp .env.example .env
```

Contenido del `.env`:
```env
PORT=8081
SPRING_DATASOURCE_URL=jdbc:oracle:thin:@clx44joct2djmlz9_high?TNS_ADMIN=/app/wallet
SPRING_DATASOURCE_USERNAME=ADMIN
SPRING_DATASOURCE_PASSWORD=TuPasswordDeAdmin
AZURE_TENANT_ID=3fb8463e-0e33-4b7d-adc1-2a47c707831e
AZURE_CLIENT_ID=9494b59c-9c6e-4a0f-91ae-ae90212882e7
CORS_ALLOWED_ORIGINS=http://localhost:4200
```

---

## Quick start (desarrollo local)

1. Asegúrate de tener la carpeta del Wallet en `src/main/resources/wallet/`.
2. En Windows (PowerShell) o Linux, exporta las variables o permite que Spring Boot tome los defaults de `application.yaml`:

```bash
export PORT=8081
export SPRING_DATASOURCE_URL="jdbc:oracle:thin:@clx44joct2djmlz9_high?TNS_ADMIN=C:/Users/GAMER/Desktop/DigitalFix/digitalfix-ms-login/src/main/resources/wallet"
export SPRING_DATASOURCE_USERNAME=ADMIN
export SPRING_DATASOURCE_PASSWORD=TuPassword
export AZURE_TENANT_ID=<AZURE_TENANT_ID>
export AZURE_CLIENT_ID=<AZURE_CLIENT_ID>
```

3. Ejecutar el servicio con Maven Wrapper:

```bash
./mvnw spring-boot:run
```

El servicio queda disponible en `http://localhost:8081`. Al iniciar, Flyway aplica las migraciones ubicadas en `src/main/resources/db/migration`.

---

## Seguridad

La seguridad vive en el paquete [`security`](src/main/java/df/digitalfix_ms_login/security). Sigue el modelo RBAC del backend de referencia (reglas centralizadas por ruta y autoridades `ROLE_*`), pero **no emite tokens propios**: autentica Microsoft Entra ID (IDaaS) y el servicio solo valida su JWT como **OAuth2 Resource Server**.

**Validación del token** ([`SpringSecurityConfig`](src/main/java/df/digitalfix_ms_login/security/SpringSecurityConfig.java), `JwtDecoder`):

| Qué se valida | Cómo |
|---|---|
| Firma | Con las claves públicas (JWKS) del tenant, descubiertas desde el issuer (RS256). |
| Vigencia | Claims `exp` y `nbf`. |
| Issuer | `https://login.microsoftonline.com/<AZURE_TENANT_ID>/v2.0`. |
| Audiencia | `aud` igual a `AZURE_CLIENT_ID` o `api://<AZURE_CLIENT_ID>`. |
| Punto limpio | [`TokenIssuedAfterLogoutValidator`](src/main/java/df/digitalfix_ms_login/security/TokenIssuedAfterLogoutValidator.java) rechaza los tokens emitidos antes del último `LOGOUT` del usuario. |

**Autoridades** ([`EntraJwtAuthenticationConverter`](src/main/java/df/digitalfix_ms_login/security/EntraJwtAuthenticationConverter.java)):

- `SCOPE_<scope>` por cada scope del claim `scp` (por ejemplo `SCOPE_access_as_user`).
- `ROLE_<ROL>` por cada App Role del claim `roles` del token.
- `ROLE_<ROL>` con el rol del usuario en **ms-user** (`USUARIOS.ID_ROL → ROLES.CODIGO`), consultado en `GET /api/user/me` reenviando el mismo JWT ([`UserRoleClient`](src/main/java/df/digitalfix_ms_login/service/UserRoleClient.java), caché de 5 minutos por usuario). Si ms-user no responde, solo pasan las rutas que piden el scope.

**Errores** ([`JsonSecurityErrorHandler`](src/main/java/df/digitalfix_ms_login/security/JsonSecurityErrorHandler.java)), con el mismo formato JSON que `GlobalExceptionHandler`:

- `401 Unauthorized` (+ cabecera `WWW-Authenticate: Bearer`): falta el token, la firma no es válida, expiró, issuer/audiencia incorrectos o es anterior al último logout. El motivo va en `errors`.
- `403 Forbidden`: el token es válido pero no tiene el scope o el rol que exige la ruta.

La sesión es **stateless** y CSRF está deshabilitado. **CORS** permite los orígenes de `CORS_ALLOWED_ORIGINS`.

---

## Endpoints

| Método | Ruta | Protección | Descripción |
|---|---|---|---|
| GET | `/api/v1/login/status` | Scope `access_as_user` | Confirma que la autenticación contra Entra ID fue exitosa. |
| GET | `/api/v1/login/me` | Scope `access_as_user` | Identidad, roles y scopes del usuario según el token validado. Lo usa el frontend para armar las vistas por rol. |
| POST | `/api/v1/login/logout` | Scope `access_as_user` | Registra el `LOGOUT`; desde ese momento se rechazan los tokens emitidos antes. Responde `204`. |
| POST | `/api/v1/audit/login` | Scope `access_as_user` | Registra un intento de inicio de sesión (éxito, fallo o cuenta bloqueada). |
| GET | `/api/v1/audit/login` | Rol `ADMIN` o `AUDITOR` | Últimos 50 eventos de auditoría de acceso. |
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

- Respuesta exitosa: `201 Created` sin cuerpo.

Colección de Postman disponible en [`postman/digitalfix-ms-login.postman_collection.json`](postman/digitalfix-ms-login.postman_collection.json).

---

## Base de datos

El esquema se gestiona con Flyway en Oracle Autonomous Database. La migración inicial [`V1__crear_tabla_auditoria_login.sql`](src/main/resources/db/migration/V1__crear_tabla_auditoria_login.sql) crea la tabla `LOG_AUDITORIA_ACCESO`:

| Columna | Tipo | Descripción |
|---|---|---|
| `ID` | `NUMBER(19,0)` | Identidad autogenerada, llave primaria. |
| `USER_ENTRA_ID` | `VARCHAR2(100)` | Identificador del usuario en Microsoft Entra ID. |
| `EVENTO` | `VARCHAR2(50)` | Tipo de evento (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `ACCOUNT_BLOCKED`). |
| `DIRECCION_IP` | `VARCHAR2(45)` | Dirección IP de origen del intento. |
| `USER_AGENT` | `VARCHAR2(500)` | Cliente o navegador desde el que se realizó el intento. |
| `FECHA_REGISTRO` | `TIMESTAMP` | Fecha y hora de registro del evento. |
| `MOTIVO_FALLO` | `VARCHAR2(255)` | Descripción o detalle en caso de fallo (sincronizado vía JPA). |

---

## Dockerización

El proyecto cuenta con un `Dockerfile` multi-stage optimizado para producción y un `docker-compose.yaml` configurado para conectarse directamente a la base de datos Oracle en la nube (OCI) usando el Wallet.

### Detalle del Dockerfile

- **Etapa `builder`**: imagen `maven:3.9.8-eclipse-temurin-21-alpine`, descarga dependencias y compila el `.jar`.
- **Etapa final**: imagen liviana `eclipse-temurin:21-jre-alpine`:
  - Ejecuta con un usuario no root (`spring:spring`).
  - Incluye el `.jar` y copia el Wallet a `/app/wallet`.
  - Expone el puerto `8081`.
  - Agrega `-Djava.net.preferIPv4Stack=true` a `JAVA_OPTS` para garantizar conectividad IPv4 estable con Microsoft Entra ID y OCI.

### Build y ejecución con Docker standalone

```bash
docker build -t digitalfix-ms-login .
docker run --rm -p 8081:8081 \
  --env-file .env \
  --name digitalfix-ms-login digitalfix-ms-login
```

### Ejecución con Docker Compose

El `docker-compose.yaml` levanta el microservicio conectado a la red común `digitalfix-net` para integrarse con los demás servicios y el futuro API Gateway:

```bash
# Levantar el servicio
docker compose up -d --build

# Ver logs en tiempo real
docker compose logs -f ms-login

# Detener el servicio
docker compose down
```

---

## Despliegue en AWS / EC2

El workflow [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) despliega automáticamente a una instancia EC2 (Ubuntu) en cada push a la rama `deploy`:

1. Compila el proyecto con Maven para validar que no haya errores de compilación ni de empaquetado.
2. Se conecta por SSH a la instancia EC2.
3. Actualiza el código (`git fetch` + `git reset --hard origin/deploy`).
4. Ejecuta `docker compose up -d --build`, levantando la aplicación en el puerto `8081` y conectándose a la base de datos Oracle en OCI.
5. El puerto `8081` puede ser registrado directamente como target en un **AWS Application Load Balancer (ALB)** o integrado con **Amazon API Gateway** (HTTP API con VPC Link).

---

## Estructura del proyecto

```text
digitalfix-ms-login/
├── Dockerfile
├── docker-compose.yaml
├── .env.example              # Plantilla de variables de entorno
├── pom.xml
├── mvnw / mvnw.cmd
├── docs/
│   └── configuracion-bd.md   # Guía completa OCI, Wallet mTLS y Troubleshooting
├── postman/                  # Colección de pruebas de endpoints
└── src/
    ├── main/
    │   ├── java/df/digitalfix_ms_login/
    │   │   ├── config/       # SecurityConfig y configuración de CORS
    │   │   ├── controller/   # Endpoints REST (LoginController, AuditController)
    │   │   ├── dto/          # DTOs de petición y respuesta
    │   │   ├── model/        # Entidad LoginAudit
    │   │   ├── repository/   # LoginAuditRepository
    │   │   └── service/      # LoginAuditService
    │   └── resources/
    │       ├── application.yaml
    │       ├── wallet/       # Certificados y configuración mTLS de Oracle
    │       └── db/migration/ # Scripts de Flyway
    └── test/
```
