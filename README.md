# Auth Service

Authentication Service for OAuth2 with Google. It maintains Redis-backed authenticated browser sessions and supports Single Sign-On (SSO) for multiple UI applications.

## Features

- OAuth2 login flow with Google
- Single Sign-On (SSO) support for multiple UI apps
- User creation and management
- Redis-backed browser session cookie (HttpOnly)
- Shared database with EMS Service for user data
- Session-based authentication with Redis

## Prerequisites

- Java 17
- Maven
- PostgreSQL database (shared with EMS service)
- Redis (for session storage)
- Google OAuth2 credentials

## Configuration

### Environment Variables

Set the following environment variables:

```bash
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Database

The Auth Service uses the same database as the EMS Service:
- Database: `emsdb`
- Host: `localhost:5432`
- Username: `postgres`
- Password: `postgres`

### Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to APIs & Services → Credentials
3. Create OAuth 2.0 Client ID (Web application type)
4. Add authorized redirect URI: `http://localhost:8081/login/oauth2/code/google`
5. Copy Client ID and Client Secret

## Running the Service

### 1. Start Redis

Using Docker Compose (recommended):
```bash
docker-compose up -d
```

Or manually:
```bash
docker run -d -p 6379:6379 --name auth-service-redis redis:7-alpine
```

### 2. Start Auth Service

```bash
mvn spring-boot:run
```

The service will start on port 8081 and connect to Redis on localhost:6379.

## API Endpoints

### GET /auth/login
Initiates OAuth2 login flow - redirects to Google.

**Query Parameters:**
- `returnUrl` (optional): URL to redirect to after successful login. Must be in the whitelist of allowed return URLs.

**Example:**
```
GET /auth/login?returnUrl=http://localhost:4201/dashboard
```

### GET /auth/success
Handles successful OAuth2 authentication, requires successful user provisioning, and redirects to returnUrl (or default frontend URL). Google ID tokens are not copied into an application cookie.

### POST /auth/logout
Clears the authentication cookie and session.

### GET /auth/user
Returns current user information. Returns 401 if not authenticated. Used by UI apps to check authentication status.

**Response:**
- `200 OK`: User is authenticated, returns user info with roles
- `401 Unauthorized`: User is not authenticated

## Architecture

- **User Management**: Creates and manages users in shared database
- **Role Management**: Handled by EMS Service (roles are business logic)
- **Browser authentication**: Redis-backed Spring Session with an HttpOnly cookie (not accessible to JavaScript)
- **Session Storage**: Redis (enables horizontal scalability and session persistence)
- **Cookie Domain**: Configured in `application.properties` (empty for localhost)
- **SSO Support**: Session-based authentication allows multiple apps to share the same session via Redis

## Integration with EMS Service

The Auth Service:
1. Creates users during OAuth2 callback
2. Sets JWT in HttpOnly cookie
3. EMS Service validates JWT from cookie (via CookieJwtExtractorFilter)
4. EMS Service manages roles and assigns them to users

## Development

### Port
- Auth Service: `8081`
- EMS Service: `8080`
- Frontend: `4200`

### Session Cookie Configuration
- Cookie name: Spring Session default (`SESSION`), configurable by the deployment
- HttpOnly: `true`
- Secure: `false` in the explicit local profile, `true` in production
- SameSite: `lax`
- Server-side session timeout: `30 minutes`

### Session Configuration
- **Storage**: Redis (shared across instances)
- **Session Timeout**: 30 minutes
- **Session Cookie**: `JSESSIONID` (managed by Spring Session)
- **Benefits**: 
  - Sessions survive server restarts
  - Horizontal scalability (multiple instances share sessions)
  - Production-ready session management
  - SSO support: Multiple UI apps can share the same session

## Single Sign-On (SSO) Configuration

### How SSO Works

1. **User visits any UI app** (e.g., `localhost:4200` or `localhost:4201`)
   - App calls `/auth/user` to check authentication status
   - If not authenticated, redirects to `/auth/login?returnUrl=<app-url>`

2. **User authenticates via auth-service**
   - Auth service stores session in Redis
   - Sets cookies for `localhost:8081` (auth-service domain)
   - Redirects back to originating app via `returnUrl`

3. **User visits another app**
   - App calls `/auth/user` with `withCredentials: true`
   - Browser automatically sends cookies to auth-service
   - Auth service validates session from Redis
   - Returns user info - user is authenticated across all apps!

### Configuration for Multiple Apps

**File:** `src/main/resources/application-local.yaml`

```yaml
# CORS Configuration - Add all UI app origins
cors:
  allowed-origins: http://localhost:4200,http://localhost:4201,http://localhost:4202

# Whitelist of allowed return URLs for security
auth:
  allowed-return-urls: http://localhost:4200,http://localhost:4201,http://localhost:4202
```

### Adding a New UI App

1. **Update CORS configuration:**
   - Add the new app's origin to `cors.allowed-origins` in `application-local.yaml`

2. **Update return URL whitelist:**
   - Add the new app's URL to `auth.allowed-return-urls` in `application-local.yaml`

3. **Configure Angular app:**
   - Set `authServiceUrl` to `http://localhost:8081`
   - Use `withCredentials: true` for all requests to auth-service
   - Call `/auth/user` on app initialization to check authentication status

### Security Notes

- **Return URL Validation**: Only URLs in the whitelist are allowed to prevent open redirect attacks
- **Cookie Security**: Cookies are HttpOnly and set for auth-service domain only
- **Session Sharing**: Sessions are stored in Redis and validated via API calls
- **CORS**: Only whitelisted origins can access auth-service APIs
- **User Service calls**: Auth Service sends `X-Internal-Api-Key` to the protected User Service API. Set the same `USER_SERVICE_API_KEY` value for both services; do not commit it.
- **CSRF**: Browser state-changing endpoints use Spring Security CSRF protection. A browser client must send the CSRF token header with cookie-authenticated writes such as logout.
