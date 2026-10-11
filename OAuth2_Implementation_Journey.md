# OAuth2 Implementation Journey

## Table of Contents
1. [Initial Requirements & Questions](#initial-requirements--questions)
2. [Implementation Approach](#implementation-approach)
3. [Key Decisions & Rationale](#key-decisions--rationale)
4. [Architecture Details](#architecture-details)
5. [Configuration Details](#configuration-details)
6. [Testing & Usage](#testing--usage)
7. [Common Questions Answered](#common-questions-answered)

---

## Initial Requirements & Questions

### Original Request
Secure REST endpoints using OAuth 2.0 with Google as the identity provider.

### Questions Asked & Decisions Made

#### 1. Resource Server vs OAuth2 Client
**Question**: What type of OAuth2 implementation do you need?

**Options Considered**:
- Resource Server: Backend validates JWT tokens sent by frontend
- OAuth2 Client: Backend handles Google login flow (redirects to Google)
- Both: Support both login flow and token validation

**Decision**: Resource Server only

**Rationale**: 
- Frontend/client handles Google login separately
- Backend only validates tokens
- Stateless architecture (no sessions)
- Standard pattern for API-only backends

#### 2. Which Endpoints to Secure
**Question**: Which endpoints should be secured with OAuth 2.0?

**Decision**: All REST endpoints under `/api/v1/**`

**Rationale**: Complete API protection while keeping public endpoints (Swagger, Actuator health) accessible.

#### 3. How to Test in Postman
**Question**: How can I get a token to test in Postman?

**Solution**: Use Google OAuth2 Playground
- Go to https://developers.google.com/oauthplayground/
- Configure with your Client ID and Secret
- Select scopes: `openid`, `email`, `profile`
- Get ID Token (not Access Token)
- Use ID Token in Postman: `Authorization: Bearer <id_token>`

#### 4. Redirect URI Confusion
**Question**: What should be the redirect URL for Resource Server?

**Clarification**: 
- Redirect URI is **NOT needed** for Resource Server
- Redirect URI is only for OAuth2 Client (when backend handles login)
- Resource Server only validates tokens, doesn't handle login flow
- The redirect URI you configured (`http://localhost:8080/login/oauth2/code/google`) is for future OAuth2 Client implementation

#### 5. Access Token vs ID Token
**Question**: We generally use access_token, is it?

**Discovery**: 
- Google's `access_token` is **opaque** (starts with `ya29.`)
- Google's `id_token` is **JWT format** (starts with `eyJ`)
- Resource Server needs JWT format to validate locally

**Decision**: Use ID Token

**Why**:
- ID Token is JWT (self-contained, can validate locally)
- Access Token is opaque (requires Google API call to validate)
- ID Token contains user identity information (email, name, etc.)

**Token Response Example**:
```json
{
  "access_token": "ya29.a0Aa7pCA...",  // Opaque - NOT used
  "id_token": "eyJhbGciOiJSUzI1NiIs...", // JWT - USED for Resource Server
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

#### 6. Audience Validation
**Question**: What is audience validation?

**Answer**: 
Audience validation ensures the JWT token was issued for your application (not another app).

**How it works**:
- JWT contains `aud` (audience) claim with Client ID
- Validator checks if `aud` matches your configured Client ID
- Prevents token misuse (token from App A used in App B)

**Implementation**: Custom `AudienceValidator` in SecurityConfig

#### 7. JwtDecoder Explanation
**Question**: What does JwtDecoder do and what does it provide?

**Answer**:
- **What it does**: Validates JWT signature, expiration, issuer, audience
- **What it provides**: `Jwt` object with all claims (email, name, Google ID, etc.)
- **How it works**: Uses Google's public keys (fetched from `https://accounts.google.com/.well-known/openid-configuration`)

**After validation**: Creates `JwtAuthenticationToken` with user information and roles.

#### 8. Role Configuration
**Question**: Can I configure roles for users?

**Options Considered**:
- Roles from JWT claims (requires Google Workspace)
- Database-based roles (flexible, manageable)
- Email/domain mapping (simple but limited)

**Decision**: Database-based roles

**Why**:
- Works with regular Google accounts (no Workspace needed)
- Flexible role management
- Easy to assign/change roles
- Supports complex role hierarchies

#### 9. Authorization Without Roles
**Question**: How does it authorize now without roles?

**Answer**:
- **Current state**: Only authentication (valid Google user?)
- **Without roles**: All authenticated users have same access
- **With roles**: Different users have different permissions
- **Implementation**: Added role-based authorization after this question

#### 10. Security Filters and Providers
**Question**: What security filters and authorization providers are we using?

**Answer**:
- **Filter**: `OAuth2ResourceServerJwtAuthenticationFilter` (extracts Bearer token)
- **Filter**: `FilterSecurityInterceptor` (enforces authorization rules)
- **Provider**: `JwtAuthenticationProvider` (implicit, validates JWT)
- **Decoder**: `NimbusJwtDecoder` (validates JWT signature)

---

## Implementation Approach

### Phase 1: OAuth2 Resource Server Setup

**Dependency Added**:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

**SecurityConfig Configuration**:
- Configured OAuth2 Resource Server
- Set up JWT decoder with Google issuer URI
- Added audience validation
- Secured `/api/v1/**` endpoints
- Kept public endpoints accessible (Swagger, Actuator)

**Key Code**:
```java
.oauth2ResourceServer(oauth2 -> oauth2
    .jwt(jwt -> jwt
        .decoder(jwtDecoder())
        .jwtAuthenticationConverter(jwtAuthenticationConverter)
    )
)
```

### Phase 2: Token Handling

**Understanding Token Types**:
- **Access Token**: Opaque, used for Google API calls (not used in Resource Server)
- **ID Token**: JWT format, contains user identity (used in Resource Server)

**Token Validation Process**:
1. Extract Bearer token from `Authorization` header
2. Validate signature using Google's public keys
3. Check expiration (`exp` claim)
4. Verify issuer (`iss` claim = `https://accounts.google.com`)
5. Validate audience (`aud` claim = your Client ID)

**Audience Validation Implementation**:
```java
private static class AudienceValidator implements OAuth2TokenValidator<Jwt> {
    // Validates token's audience matches configured Client ID
}
```

### Phase 3: Role-Based Access Control

**Database Schema Created**:
- `users` table: Stores Google user info (email, Google ID, name, picture)
- `roles` table: Stores roles (ADMIN, HR, MANAGER, USER)
- `user_roles` table: Many-to-many relationship

**Entities Created**:
- `Role` entity with enum: ADMIN, HR, MANAGER, USER
- `User` entity with Google integration
- `UserRepository` with role fetching queries
- `RoleRepository` for role management

**UserRoleService**:
- Fetches roles from database based on Google email/ID
- Creates new users automatically on first login
- Assigns default USER role to new users
- Updates user info if changed (name, picture)

**JwtAuthenticationConverter**:
- Extracts user info from JWT (email, Google ID, name, picture)
- Calls UserRoleService to get roles
- Converts roles to Spring Security authorities (`ROLE_ADMIN`, `ROLE_HR`, etc.)
- Creates JwtAuthenticationToken with roles

**Automatic User Creation**:
- On first login: User doesn't exist in database
- System creates user with default USER role
- Admin can later assign higher roles via database

### Phase 4: Security Architecture

**Security Filter Chain**:
1. `OAuth2ResourceServerJwtAuthenticationFilter`: Extracts Bearer token
2. `FilterSecurityInterceptor`: Enforces authorization rules

**Authentication Provider**:
- `JwtAuthenticationProvider` (implicit, configured by Spring Security)
- Uses `NimbusJwtDecoder` to validate JWT
- Uses custom `JwtAuthenticationConverter` to add roles

**Endpoint Protection Rules**:
```java
.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
.requestMatchers("/api/v1/employees/**").hasAnyRole("ADMIN", "HR")
.requestMatchers("/api/v1/departments/**").authenticated()
.requestMatchers("/api/v1/reports/**").hasAnyRole("ADMIN", "HR")
```

---

## Key Decisions & Rationale

### Decision 1: Resource Server vs OAuth2 Client

**Chosen**: Resource Server

**Why**:
- Frontend handles Google login flow
- Backend only validates tokens (stateless)
- No redirect URI needed
- Standard pattern for REST APIs
- Better separation of concerns

**Alternative Considered**: OAuth2 Client
- Would require redirect URI
- Backend handles login flow
- More complex for API-only backend

### Decision 2: ID Token vs Access Token

**Chosen**: ID Token

**Why**:
- JWT format (can validate locally)
- Contains user identity information
- No need to call Google API for validation
- Self-contained token

**Alternative**: Access Token
- Opaque format (requires Google API call)
- Used for Google API calls, not identity
- Would need additional validation endpoint

### Decision 3: Database Roles vs JWT Claims

**Chosen**: Database-based roles

**Why**:
- Works with regular Google accounts (no Workspace needed)
- Flexible role management
- Easy to assign/change roles
- Supports complex hierarchies
- Can be managed via admin interface

**Alternative Considered**: JWT Claims
- Requires Google Workspace
- Roles embedded in token (harder to change)
- Limited flexibility

### Decision 4: Automatic User Creation

**Chosen**: Create user on first login with default USER role

**Why**:
- Seamless user experience
- No manual user registration needed
- Admin can later assign higher roles
- User info synced from Google

**Implementation**:
- UserRoleService checks if user exists
- If not, creates user with USER role
- Updates user info if changed

---

## Architecture Details

### Security Filters Used

#### 1. OAuth2ResourceServerJwtAuthenticationFilter
- **Position**: Early in filter chain
- **Purpose**: Extracts Bearer token from `Authorization` header
- **Action**: Passes token to JwtDecoder for validation

#### 2. FilterSecurityInterceptor
- **Position**: After authentication
- **Purpose**: Enforces authorization rules
- **Action**: Checks roles and allows/denies requests

### Authentication Provider

#### JwtAuthenticationProvider (Implicit)
- **Type**: `AuthenticationProvider`
- **Components**:
  - `NimbusJwtDecoder`: Validates JWT signature
  - `JwtAuthenticationConverter`: Adds roles to authentication

**Flow**:
```
JWT Token → JwtDecoder → Jwt Object → JwtAuthenticationConverter → JwtAuthenticationToken (with roles)
```

### Components Created

1. **Role Entity** (`Role.java`)
   - Enum: ADMIN, HR, MANAGER, USER
   - Many-to-many with User

2. **User Entity** (`User.java`)
   - Google ID, email, name, picture
   - Many-to-many with Role

3. **Repositories**
   - `RoleRepository`: Role queries
   - `UserRepository`: User queries with role fetching

4. **UserRoleService**
   - Fetches roles from database
   - Creates users automatically
   - Updates user info

5. **JwtAuthenticationConverter**
   - Extracts user info from JWT
   - Gets roles from database
   - Creates authentication with authorities

6. **SecurityConfig Updates**
   - OAuth2 Resource Server configuration
   - JWT decoder setup
   - Role-based endpoint protection

### Request Flow Diagram

```mermaid
sequenceDiagram
    participant Client
    participant OAuth2Filter as OAuth2ResourceServerJwtAuthenticationFilter
    participant JwtDecoder as NimbusJwtDecoder
    participant Converter as JwtAuthenticationConverter
    participant UserService as UserRoleService
    participant AuthProvider as JwtAuthenticationProvider
    participant FilterSec as FilterSecurityInterceptor
    participant Controller
    
    Client->>OAuth2Filter: Request with Bearer token
    OAuth2Filter->>JwtDecoder: Extract & validate JWT
    JwtDecoder->>JwtDecoder: Validate signature, expiration, issuer, audience
    JwtDecoder->>Converter: Return Jwt object
    Converter->>UserService: Get roles for user (email, googleId)
    UserService->>UserService: Query database for roles
    UserService->>Converter: Return Collection<GrantedAuthority>
    Converter->>AuthProvider: Create JwtAuthenticationToken with roles
    AuthProvider->>FilterSec: Authentication object with authorities
    FilterSec->>FilterSec: Check authorization rules<br/>(hasRole, hasAnyRole)
    
    alt Authorized
        FilterSec->>Controller: Allow request
        Controller->>Client: 200 OK + Response
    else Unauthorized
        FilterSec->>Client: 403 Forbidden
    end
```

---

## Configuration Details

### application.yaml

**OAuth2 Resource Server Configuration**:
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://accounts.google.com
```

**Google Credentials**:
```yaml
google:
  client-id: ${GOOGLE_CLIENT_ID:your-google-client-id-here}
  client-secret: ${GOOGLE_CLIENT_SECRET:your-google-client-secret-here}
  redirect-uri: http://localhost:8080/login/oauth2/code/google
```

**Note**: 
- Client ID: Used for audience validation
- Client Secret: Not used by Resource Server (for OAuth2 Client only)
- Redirect URI: Not used by Resource Server (for OAuth2 Client only)

### SecurityConfig

**JWT Decoder Configuration**:
```java
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
        .withIssuerLocation(issuerUri)
        .build();
    
    // Add validators
    OAuth2TokenValidator<Jwt> withIssuer = 
        JwtValidators.createDefaultWithIssuer(issuerUri);
    OAuth2TokenValidator<Jwt> audienceValidator = 
        new AudienceValidator(clientId);
    
    jwtDecoder.setJwtValidator(
        new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator)
    );
    
    return jwtDecoder;
}
```

**Endpoint Protection**:
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/actuator/health", "/actuator/info").permitAll()
    .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
    .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/v1/employees/**").hasAnyRole("ADMIN", "HR")
    .requestMatchers("/api/v1/departments/**").authenticated()
    .requestMatchers("/api/v1/reports/**").hasAnyRole("ADMIN", "HR")
    .requestMatchers("/api/v1/**").authenticated()
    .anyRequest().authenticated()
)
```

### Database Schema

**Users Table**:
```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    google_id VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(100),
    picture VARCHAR(500),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    version BIGINT
);
```

**Roles Table**:
```sql
CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(200)
);
```

**User_Roles Table**:
```sql
CREATE TABLE user_roles (
    user_id BIGINT REFERENCES users(id),
    role_id BIGINT REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);
```

**Initial Data (data.sql)**:
```sql
-- Insert Roles
INSERT INTO roles (name, description) VALUES
    ('ADMIN', 'Administrator with full access'),
    ('HR', 'Human Resources - can manage employees'),
    ('MANAGER', 'Department Manager'),
    ('USER', 'Regular user - basic access');

-- Insert Users (update with your Google info)
INSERT INTO users (google_id, email, name, created_at, updated_at, version)
VALUES ('YOUR_GOOGLE_ID', 'your-email@gmail.com', 'Your Name', 
        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0);

-- Assign Roles
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'your-email@gmail.com' AND r.name = 'ADMIN';
```

---

## Testing & Usage

### Getting Tokens

**Using Google OAuth2 Playground**:

1. Go to https://developers.google.com/oauthplayground/
2. Click gear icon (⚙️) → Check "Use your own OAuth credentials"
3. Enter your Client ID and Client Secret
4. Select scopes:
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/userinfo.profile`
   - `openid`
5. Click "Authorize APIs" → Sign in with Google
6. Click "Exchange authorization code for tokens"
7. **Copy the ID Token** (starts with `eyJ...`)

**Important**: Use **ID Token**, not Access Token!

### Making Requests

**Postman**:
1. Set Authorization type: `Bearer Token`
2. Paste your ID Token
3. Make request to `http://localhost:8080/api/v1/employees`

**curl**:
```bash
curl --location 'http://localhost:8080/api/v1/employees' \
--header 'Authorization: Bearer eyJhbGciOiJSUzI1NiIs...'
```

**Response Codes**:
- `200 OK`: Request successful
- `401 Unauthorized`: Invalid or missing token
- `403 Forbidden`: Valid token but insufficient permissions

### Role Assignment

**Initial Setup**:
- Roles are created via `data.sql` on application startup
- Users are created automatically on first login with USER role

**Manual Role Assignment** (via SQL):
```sql
-- Assign ADMIN role to user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'user@example.com' AND r.name = 'ADMIN';

-- Assign multiple roles
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.email = 'user@example.com' 
  AND r.name IN ('ADMIN', 'HR');
```

**Future Enhancement**: Admin interface for role management

---

## Common Questions Answered

### Q1: What is audience validation?

**A**: Audience validation ensures the JWT token was issued for your application. It checks that the token's `aud` (audience) claim matches your configured Client ID. This prevents tokens from other applications from being used in your API.

**Example**: If App A has Client ID `client-id-A` and App B has `client-id-B`, a token issued for App A (with `aud: client-id-A`) will be rejected by App B if audience validation is enabled.

### Q2: What does JwtDecoder do?

**A**: JwtDecoder validates and decodes JWT tokens:
- Validates signature using Google's public keys
- Checks expiration (`exp` claim)
- Verifies issuer (`iss` claim)
- Validates audience (`aud` claim)
- Returns `Jwt` object with all claims (email, name, Google ID, etc.)

After validation, Spring Security creates a `JwtAuthenticationToken` that can be used throughout your application.

### Q3: How does authorization work without roles?

**A**: Without roles, the system only performs **authentication** (is this a valid Google user?). All authenticated users have the same access. With roles, the system performs **authorization** (what can this user do?), allowing different users to have different permissions.

**Before roles**: `authenticated()` → All valid Google users can access
**After roles**: `hasRole("ADMIN")` → Only users with ADMIN role can access

### Q4: What security filters are used?

**A**: 
- **OAuth2ResourceServerJwtAuthenticationFilter**: Extracts Bearer token from request
- **FilterSecurityInterceptor**: Enforces authorization rules (role checks)

### Q5: What authentication provider is used?

**A**: 
- **JwtAuthenticationProvider** (implicit, configured by Spring Security)
- Uses **NimbusJwtDecoder** to validate JWT
- Uses custom **JwtAuthenticationConverter** to add roles

### Q6: Why use ID Token instead of Access Token?

**A**: 
- **ID Token**: JWT format, can be validated locally, contains user identity
- **Access Token**: Opaque format, requires Google API call to validate, used for Google API calls

Resource Server needs JWT format to validate tokens locally without network calls.

### Q7: How are roles assigned?

**A**: 
- **Automatic**: New users get USER role on first login
- **Manual**: Admin assigns roles via database (SQL)
- **Future**: Admin interface for role management

### Q8: How does automatic user creation work?

**A**: 
1. User sends request with valid JWT token
2. System extracts email and Google ID from JWT
3. Checks if user exists in database
4. If not found, creates new user with default USER role
5. Updates user info (name, picture) if changed
6. Returns roles as Spring Security authorities

This provides seamless user experience - no manual registration needed.

---

## Summary

This implementation provides:
- ✅ OAuth2 Resource Server with Google as identity provider
- ✅ JWT token validation (ID Token)
- ✅ Database-based role management
- ✅ Automatic user creation
- ✅ Role-based endpoint protection
- ✅ Stateless architecture (no sessions)
- ✅ Secure and scalable design

**Key Takeaway**: The backend validates tokens and enforces authorization, while the frontend handles the OAuth2 login flow. This separation provides flexibility and follows best practices for REST API security.



