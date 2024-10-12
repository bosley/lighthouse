# Lighthouse Authentication Server

Welcome to the Lighthouse Authentication Server. This application provides a secure and efficient authentication system utilizing JWT tokens. It's designed to handle user registration, email verification (TODO), login, and token management, including blacklisting. This README will guide you through the API endpoints, token usage, and the inner workings of the application.

## Table of Contents

- [API Endpoints](#api-endpoints)
- [Token Usage](#token-usage)
- [Under the Hood](#under-the-hood)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Database Structure](#database-structure)

## API Endpoints

| Endpoint                               | Method | Description                                    |
|----------------------------------------|--------|------------------------------------------------|
| `/api/v1/users/new`                    | POST   | Register a new user                            |
| `/api/v1/verify`                       | GET    | Verify a user's email                          |
| `/api/v1/auth`                         | POST   | Authenticate a user and obtain a JWT token     |
| `/api/v1/vip/blacklist/:token`         | GET    | Blacklist a JWT token (requires authentication)|

## Token Usage

The application uses JWT (JSON Web Tokens) for authenticating users and managing session state. Tokens are issued upon successful login and are required to access protected routes. They include claims like `sub` (subject/user ID), `exp` (expiration time), `iat` (issued at), and `jti` (JWT ID).

### Token Lifecycle

1. **Registration**: A user registers via `/api/v1/users/new`, providing an email, username, and password.
2. **Email Verification**: The server generates a verification token, encodes it in base64, and sends it back. The user verifies their email using `/api/v1/verify`, providing the token in the `Lighthouse-Magic-Link` header.
3. **Login**: The user logs in via `/api/v1/auth`, supplying their credentials. If valid, the server issues a JWT authentication token.
4. **Protected Access**: The JWT token is used in the `Lighthouse-Token` header to access protected endpoints.
5. **Token Blacklisting**: Tokens can be blacklisted using `/api/v1/vip/blacklist/:token`. Blacklisted tokens are invalidated and cannot be used for authentication.

### Token Claims

- **sub**: Subject. The user's unique ID in the system.
- **exp**: Expiration time. When the token becomes invalid.
- **iat**: Issued at. The time when the token was generated.
- **jti**: JWT ID. A unique identifier for the token.

## Under the Hood

The server is built with Go and the Gin web framework. It utilizes GORM for ORM functionality with a SQLite database. Below is an overview of key components and processes:

### Server Initialization

- **Router Setup**: Initializes Gin router with middleware for rate limiting and authentication.
- **TLS Configuration**: Supports TLS with options to generate self-signed certificates if none are provided.
- **Server Start**: Listens and serves HTTPS requests on the specified port.

### User Registration and Verification

- **Password Hashing**: User passwords are hashed using bcrypt before storage.
- **Email Verification Token**: A JWT token is generated upon registration for email verification.
- **Verification Process**: The user supplies the verification token to confirm their email address.

### Authentication

- **Credential Validation**: Validates user credentials against stored data.
- **JWT Token Generation**: Issues a JWT for authenticated sessions. The token includes important claims and is stored in the database.
- **Token Storage**: Tokens are associated with users and stored for management and blacklisting.

### Protected Routes and Token Blacklisting

- **Token Authentication Middleware**: Validates incoming tokens against the database and checks for blacklisting.
- **Blacklist Functionality**: Allows users to invalidate tokens via the `/api/v1/vip/blacklist/:token` endpoint.

### Rate Limiting

- **Middleware**: Implements rate limiting on certain endpoints to prevent abuse.
- **Configuration**: Limits can be adjusted as needed for different endpoints.

## Getting Started

### Prerequisites

- **Go**: Ensure Go is installed on your system.
- **Environment Variable**: Set `LIGHTHOUSE_SECRET_KEY` environment variable used for JWT signing.

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/bosley/lighthouse.git
   cd lighthouse
   ```

2. **Generate SSL Certificates**

   You can generate self-signed certificates using:

   ```bash
   go run main.go --new --ssl ./certs
   ```

3. **Initialize the Database**

   Create a new SQLite database:

   ```bash
   go run main.go --new --db ./data/lighthouse.db
   ```

### Running the Server

Start the server with:


```bash
go run main.go --cert ./certs/server.crt --key ./certs/server.key --db ./data/lighthouse.db --port :8089
```

## Configuration

**Command-Line Options:**

- `--new`: Create a new configuration (SSL certificates or database).
- `--ssl`: Directory for SSL certificate and key generation.
- `--db`: Path to the database file.
- `--cert`: Path to the SSL certificate.
- `--key`: Path to the SSL key.
- `--port`: Port to use (default `:8089`).
- `--debug`: Enable debug logging for more verbose output.

## Usage Examples

### Register a New User

**Endpoint:**

```http
POST /api/v1/users/new
```

**Request Body:**

```json
{
    "email": "user@example.com",
    "username": "johndoe",
    "password": "SecurePassword123!"
}
```

**Response:**

```json
{
    "code": 200,
    "message": "<Base64-encoded verification token>"
}
```

### Verify User Email

**Endpoint:**

```http
GET /api/v1/verify
```

**Headers:**

```
Lighthouse-Magic-Link: <Verification Token>
```

**Response:**

```json
{
    "code": 200,
    "message": "User verified successfully"
}
```

### Log In and Obtain JWT

**Endpoint:**

```http
POST /api/v1/auth
```

**Request Body:**

```json
{
    "username": "johndoe",
    "password": "SecurePassword123!",
    "requested_duration": "30m"
}
```

- `requested_duration` accepts values between `5m` and `60m`. Defaults to `60m` if invalid.

**Response:**

```json
{
    "code": 200,
    "message": "<JWT Authentication Token>"
}
```

### Access a Protected Endpoint

**Endpoint:**

```http
GET /api/v1/vip/protected
```

**Headers:**

```
Lighthouse-Token: <Your JWT Token>
```

**Response:**

```json
{
    "code": 200,
    "message": "Protected content access granted."
}
```

### Blacklist a Token

**Endpoint:**

```http
GET /api/v1/vip/blacklist/:tokenToBlacklist
```

**Headers:**

```
Lighthouse-Token: <Your JWT Token>
```

**Response:**

```json
{
    "code": 200,
    "message": "Token blacklisted successfully"
}
```

**Note:** You must be authenticated to blacklist a token.

## Database Structure

### User Model

```go
type User struct {
    gorm.Model
    Email              string `gorm:"uniqueIndex;not null"`
    Username           string `gorm:"uniqueIndex;not null"`
    PasswordBcryptHash []byte `gorm:"not null"`
    IsVerified         bool   `gorm:"default:false"`
}
```

- Stores user credentials and verification status.
- Passwords are stored as bcrypt hashes.

### TokenData Model

```go
type TokenData struct {
    gorm.Model
    AssociatedUserID uint
    AssociatedUser   User `gorm:"foreignKey:AssociatedUserID"`
    Generated        time.Time `gorm:"not null"`
    Token            string    `gorm:"uniqueIndex;not null"`
    Disabled         bool      `gorm:"default:false"`
}
```

- Stores issued JWT tokens.
- Keeps track of token generation time and disabled status for blacklisting.

### UserMeta Model

```go
type UserMeta struct {
    gorm.Model
    UserID   uint `gorm:"uniqueIndex"`
    UserData User `gorm:"foreignKey:UserID"`
}
```

- Reserved for additional user metadata.
- Currently minimal but can be extended as needed.

## Security Considerations

- **Password Hashing**: Uses bcrypt with the default cost to hash passwords securely.
- **JWT Signing**: Tokens are signed using HMAC SHA256 with a secret key provided via `LIGHTHOUSE_SECRET_KEY`.
- **TLS**: Supports HTTPS with TLS configuration. Self-signed certificates can be generated for development.
- **Rate Limiting**: Implements rate limiting on endpoints to mitigate brute-force attacks.
- **Token Blacklisting**: Tokens can be invalidated before expiration to prevent unauthorized access.

## Development Notes

- **Error Handling**: All errors are handled explicitly, and appropriate HTTP status codes are returned.
- **Deprecation**: Avoids using deprecated packages like `ioutil` in favor of modern equivalents.
- **Code Practices**: Follows good Go practices, such as proper error handling and code structure.
- **Logging**: Uses structured logging with different levels (debug, info, error) for better traceability.

## Conclusion

This authentication server provides a solid foundation for managing user authentication in your applications. It's designed with security and scalability in mind, following best practices in Go development. Feel free to explore the codebase and adapt it to your needs.

---

If you have any questions or need further assistance, please refer to the code comments or reach out.
