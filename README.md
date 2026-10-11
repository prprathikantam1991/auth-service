# Auth Service

Central authentication service for the local application ecosystem. It signs a person in with Google OpenID Connect, maintains the authenticated browser session in Redis, provisions a stable internal user through User Service, and can hand that identity to Finance Tracker without exposing a Google token to the browser application.

## What this service owns

- Google OAuth 2.0 / OpenID Connect browser login.
- Redis-backed authenticated browser sessions.
- Safe, allow-listed post-login return URLs.
- Mandatory User Service provisioning after Google verifies the person.
- Logout that invalidates the server-side Redis session.
- A short-lived, single-use Finance Tracker handoff code.

User Service remains the canonical owner of application users and roles. Finance Tracker remains the owner of finance data and its own application session.

## Architecture

```text
Browser → Auth Service → Google
             │
             ├──→ User Service (find/create stable internal user)
             │
             └──→ Finance Tracker (one-time handoff code)
                                  │
                                  └──→ Finance session + owner-scoped ledger
```

The browser never receives a Google ID token, an internal user ID, or the service credential used for the Finance handoff.

For the detailed Finance handoff contract and production hardening roadmap, see [docs/FINANCE_TRACKER_INTEGRATION.md](docs/FINANCE_TRACKER_INTEGRATION.md).

## Local prerequisites

- Java 17 or the version configured by this repository.
- Maven.
- Redis for Spring Session and short-lived handoff codes.
- PostgreSQL database used by this service.
- A Google OAuth web-client registration.
- A running User Service on port `8082`.

## Required local configuration

Set these values in the environment or local configuration; do not commit secrets.

```text
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
USER_SERVICE_API_KEY=...             # same value configured in User Service
FINANCE_HANDOFF_SERVICE_KEY=...      # same value configured in Finance Tracker
```

Google must allow this redirect URI for local development:

```text
http://localhost:8081/login/oauth2/code/google
```

The configured Finance handoff callback is normally:

```text
http://localhost:8080/api/auth/handoff/callback
```

## Run locally

1. Start Redis and User Service.
2. Start this service:

   ```powershell
   mvn spring-boot:run
   ```

3. Start Finance Tracker with authentication enabled.
4. Open the Finance Tracker frontend and select **Sign in with Google**.

The service runs on `http://localhost:8081`.

## Browser endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /auth/login?returnUrl=…` | Starts Google sign-in. The return URL must be allow-listed. |
| `GET /auth/success` | OAuth success handler; provisions the internal user and initiates the Finance handoff when appropriate. |
| `GET /auth/user` | Returns the authenticated browser user's minimal profile, or `401`. |
| `POST /auth/logout` | Requires CSRF protection and invalidates the Redis-backed browser session. |
| `POST /auth/finance/handoff/exchange` | Backend-only exchange of a one-time Finance code. It requires `X-Finance-Handoff-Key`; browsers do not call it. |

## Security model

- Authenticated browser state is a Redis-backed Spring Session cookie. It is HttpOnly; JavaScript cannot read it.
- Browser state-changing endpoints use Spring Security CSRF protection. The Finance handoff exchange is exempt because it is protected by an explicit backend service credential rather than a browser session.
- User Service calls carry `X-Internal-Api-Key`; User Service fails closed when its key is absent.
- Google identity establishes the person, but the stable User Service UUID is the application identity used by downstream services.
- The Finance handoff code expires quickly, may be used once, and is exchanged only over the backend channel.

## SSO scope

This is a practical, session-based SSO foundation for the local services: a person authenticates once with Auth Service and approved browser applications can check that authenticated session through Auth Service.

It is **not yet a complete standards-based OpenID Connect identity provider**. A production platform would add HTTPS-only deployment, a registered client model, signed JWT assertions with JWKS (or mTLS) for service trust, refresh/expiry policy, audit events, and coordinated logout across relying applications.

## Related documentation

- [Finance Tracker integration contract](docs/FINANCE_TRACKER_INTEGRATION.md)
- [User Service database ownership](../user-service/docs/DATABASE_OWNERSHIP.md)
- [Finance Tracker authentication design](../../personal-finance-tracker/docs/V7_AUTHENTICATION_AND_AUTHORIZATION_DESIGN.md)
