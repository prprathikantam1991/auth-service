# Redis Session Data Inspection Guide

## Method 1: Using Redis CLI (via Docker)

### Access Redis CLI
```bash
# If Redis is running in Docker
docker exec -it auth-service-redis redis-cli

# Or if Redis is installed locally
redis-cli
```

### View All Session Keys
```bash
# List all keys (Spring Session uses namespace: spring:session)
KEYS spring:session:*

# Or list all keys
KEYS *
```

### View Specific Session Data
```bash
# Get all session keys
KEYS spring:session:*

# View a specific session (replace SESSION_ID with actual session ID)
GET spring:session:sessions:SESSION_ID

# View session expiration info
TTL spring:session:sessions:SESSION_ID

# View session index (maps session ID to principal)
GET spring:session:index:org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME:USER_EMAIL
```

### View Session Data in Human-Readable Format
```bash
# Get session data (returns serialized data)
GET spring:session:sessions:SESSION_ID

# View all session-related keys for a session
KEYS spring:session:sessions:*SESSION_ID*

# View session expiration
TTL spring:session:sessions:SESSION_ID
```

### Useful Commands
```bash
# Count total sessions
KEYS spring:session:sessions:* | wc -l

# View all session IDs
KEYS spring:session:sessions:* | sed 's/spring:session:sessions://'

# Check if Redis is connected
PING

# Get Redis info
INFO

# Monitor real-time commands
MONITOR

# View memory usage
INFO memory
```

## Method 2: Using Redis GUI Tools

### RedisInsight (Recommended - Free)
1. Download from: https://redis.com/redis-enterprise/redis-insight/
2. Connect to: `localhost:6379`
3. Browse keys: `spring:session:*`
4. View session data in JSON format

### Redis Commander (Web-based)
```bash
# Run Redis Commander in Docker
docker run --rm \
  --name redis-commander \
  -p 8081:8081 \
  rediscommander/redis-commander:latest \
  --redis-host host.docker.internal \
  --redis-port 6379
```
Access at: http://localhost:8081

### Another Redis Desktop Manager (Another Redis Desktop Manager)
- Download from: https://github.com/qishibo/AnotherRedisDesktopManager
- Connect to: `localhost:6379`
- Browse and view session keys

## Method 3: Using Docker Exec with Scripts

### View All Sessions
```bash
docker exec -it auth-service-redis redis-cli KEYS "spring:session:*"
```

### View Session Count
```bash
docker exec -it auth-service-redis redis-cli --scan --pattern "spring:session:sessions:*" | wc -l
```

### View Session Data for Active Sessions
```bash
# Get all session keys
docker exec -it auth-service-redis redis-cli KEYS "spring:session:sessions:*"

# For each session, view its data
docker exec -it auth-service-redis redis-cli GET "spring:session:sessions:YOUR_SESSION_ID"
```

## Understanding Spring Session Keys

Spring Session stores data with these key patterns:

1. **Session Storage**: `spring:session:sessions:SESSION_ID`
   - Contains the actual session data (now in JSON format - readable!)

2. **Session Expiration**: `spring:session:sessions:expires:SESSION_ID`
   - Tracks when session expires

3. **Session Index**: `spring:session:index:org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME:PRINCIPAL`
   - Maps principal (user email) to session IDs

## JSON Serialization Benefits

With JSON serialization configured, session data is now **human-readable**! 

### Before (Java Serialization - Binary):
```
\xac\xed\x00\x05sr\x00... (unreadable binary data)
```

### After (JSON Serialization - Readable):
```json
{
  "sessionAttr:SPRING_SECURITY_CONTEXT": {
    "@class": "org.springframework.security.core.context.SecurityContextImpl",
    "authentication": {
      "@class": "org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken",
      "authorizedClientRegistrationId": "google",
      "principal": {
        "@class": "org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser",
        "email": "user@example.com",
        "name": "John Doe",
        "subject": "123456789",
        "picture": "https://lh3.googleusercontent.com/..."
      },
      "authorities": [...],
      "authenticated": true
    }
  },
  "creationTime": 1703123456789,
  "lastAccessedTime": 1703123456789,
  "maxInactiveInterval": 1800
}
```

### What You Can Now See:
- ✅ User email address
- ✅ User name
- ✅ Google user ID (subject)
- ✅ Profile picture URL
- ✅ Authentication status
- ✅ Session creation and last access times
- ✅ Any custom session attributes

## Example: Viewing a Complete Session

```bash
# 1. Connect to Redis
docker exec -it auth-service-redis redis-cli

# 2. List all sessions
KEYS spring:session:sessions:*

# 3. Get a specific session (example) - NOW READABLE AS JSON!
GET spring:session:sessions:abc123def456

# Output will be readable JSON like:
# {
#   "sessionAttr:SPRING_SECURITY_CONTEXT": {
#     "authentication": {
#       "principal": {
#         "email": "user@example.com",
#         "name": "John Doe",
#         ...
#       }
#     }
#   },
#   "creationTime": 1703123456789,
#   "lastAccessedTime": 1703123456789,
#   "maxInactiveInterval": 1800
# }

# 4. Check expiration
TTL spring:session:sessions:abc123def456

# 5. View session index (find sessions by user email)
KEYS spring:session:index:*
GET spring:session:index:org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME:user@example.com

# 6. Pretty print JSON (if you have jq installed)
GET spring:session:sessions:abc123def456 | jq .
```

## Pretty Printing JSON in Redis CLI

To make JSON more readable, you can use:

```bash
# Option 1: Use jq (if installed)
docker exec -it auth-service-redis redis-cli GET "spring:session:sessions:SESSION_ID" | jq .

# Option 2: Use Python for pretty printing
docker exec -it auth-service-redis redis-cli GET "spring:session:sessions:SESSION_ID" | python -m json.tool

# Option 3: Copy JSON and use online formatter
# Copy the output and paste into https://jsonformatter.org/

## Session Data Format

With JSON serialization configured (via `SessionConfig.java`), session data is stored as:
- **JSON strings**: Human-readable, easy to inspect and debug
- **Structured format**: Can see all session attributes, user info, timestamps
- **No binary encoding**: Directly readable in Redis CLI or any Redis GUI tool

### Key Benefits:
1. **Debugging**: Instantly see what's stored in each session
2. **Monitoring**: Easy to check active sessions and their contents
3. **Troubleshooting**: Quickly identify session-related issues
4. **Development**: Understand session lifecycle and data flow
5. **Security Auditing**: See which users have active sessions

### What You'll See:
- User authentication details (email, name, Google ID)
- Session timestamps (creation, last access)
- Session timeout settings
- Any custom session attributes
- Spring Security context information

