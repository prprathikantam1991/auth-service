# Auth Service

Authentication Service for OAuth2 with Google. Handles user authentication and sets JWT tokens in HttpOnly cookies.

## Features

- OAuth2 login flow with Google
- User creation and management
- JWT token in HttpOnly cookie (XSS safe)
- Shared database with EMS Service for user data

## Prerequisites

- Java 17
- Maven
- PostgreSQL database (shared with EMS service)
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

```bash
mvn spring-boot:run
```

The service will start on port 8081.

## API Endpoints

### GET /auth/login
Initiates OAuth2 login flow - redirects to Google.

### GET /auth/callback
Handles OAuth2 callback from Google. Creates/updates user and sets JWT in HttpOnly cookie.

### POST /auth/logout
Clears the authentication cookie.

### GET /auth/user
Returns current user information (requires authentication).

## Architecture

- **User Management**: Creates and manages users in shared database
- **Role Management**: Handled by EMS Service (roles are business logic)
- **JWT Storage**: HttpOnly cookie (not accessible to JavaScript)
- **Cookie Domain**: Configured in `application.properties` (empty for localhost)

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

### Cookie Configuration
- Cookie name: `id_token`
- HttpOnly: `true`
- Secure: `false` (development), `true` (production)
- SameSite: `strict`
- MaxAge: `3600` (1 hour)

