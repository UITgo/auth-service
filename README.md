# UITGo Auth Service

Service xử lý authentication và authorization cho UITGo, tích hợp với AWS Cognito để quản lý users và JWT tokens.

## Tổng quan

Auth service chịu trách nhiệm:
- **User Registration**: Đăng ký user mới với email/password
- **Email Verification**: Gửi và verify OTP qua email
- **Login**: Authenticate user và trả về JWT tokens
- **Token Refresh**: Refresh access token với refresh token
- **User Profile**: Lấy thông tin user từ JWT token

## Kiến trúc

Auth service sử dụng:
- **AWS Cognito**: Managed user pool cho authentication
- **MongoDB**: Lưu trữ user metadata (email, isEmailVerified, isDriver)
- **JWT**: Generate và verify JWT tokens với `JWT_SECRET`

## Endpoints

### Public Endpoints

- `POST /v1/auth/register` - Đăng ký user mới
  - Body: `{ email, password, fullname, role? }`
  - Returns: `{ message: "OTP sent to email" }`
  - Flow:
    1. Tạo user trong Cognito User Pool
    2. Gửi OTP qua email (Cognito tự động)
    3. Lưu user metadata vào MongoDB

- `POST /v1/auth/verify-otp` - Verify email với OTP
  - Body: `{ email, code }`
  - Returns: `{ message: "Email verified" }`
  - Flow:
    1. Verify OTP với Cognito
    2. Update `isEmailVerified = true` trong MongoDB

- `POST /v1/auth/login` - Đăng nhập
  - Body: `{ email, password }`
  - Returns: 
    ```json
    {
      "accessToken": "jwt-token",
      "idToken": "cognito-id-token",
      "refreshToken": "refresh-token",
      "user": {
        "email": "user@example.com",
        "isDriver": false,
        "isEmailVerified": true
      }
    }
    ```
  - Flow:
    1. Authenticate với Cognito
    2. Lấy user metadata từ MongoDB
    3. Generate JWT với `JWT_SECRET` (chứa userId, email, role)
    4. Return tokens và user info

- `POST /v1/auth/resend-otp` - Gửi lại OTP
  - Body: `{ email }`
  - Returns: `{ message: "OTP resent" }`

- `POST /v1/auth/refresh` - Refresh access token
  - Body: `{ refreshToken, email }`
  - Returns: `{ accessToken, idToken, refreshToken }`

### Protected Endpoints

- `GET /v1/auth/me` - Lấy thông tin user từ JWT
  - Headers: `Authorization: Bearer <token>`
  - Returns: User profile từ JWT payload

## JWT Token Structure

JWT token được generate với payload:
```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "role": "PASSENGER" | "DRIVER",
  "iat": 1234567890,
  "exp": 1234567890
}
```

Token được sign với `JWT_SECRET` và có expiration time (thường 1 hour).

## AWS Cognito Integration

Auth service sử dụng 2 SDKs:

1. **amazon-cognito-identity-js**: Cho user flows (register, login, verify OTP)
2. **@aws-sdk/client-cognito-identity-provider**: Cho admin operations (add user to group, get user status)

### Cognito Configuration

Cần có Cognito User Pool với:
- Email as username
- Email verification required
- Password policy (min length, complexity)
- MFA optional (hiện tại không dùng)

## Environment Variables

```bash
PORT=3000
NODE_ENV=production

# AWS Cognito
COGNITO_USER_POOL_ID=us-east-1_xxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxx
COGNITO_REGION=us-east-1

# MongoDB
MONGO_URL=mongodb://mongo:27017/uitgo

# JWT
JWT_SECRET=your-secret-key  # Must match gateway-service

# AWS Credentials (for SDK v3)
AWS_ACCESS_KEY_ID=xxxxx
AWS_SECRET_ACCESS_KEY=xxxxx
```

## Database Schema

User document trong MongoDB:
```typescript
{
  _id: ObjectId,
  authId: string,           // Cognito user ID (sub)
  email: string,
  isEmailVerified: boolean,
  isDriver: boolean,
  createdAt: Date,
  updatedAt: Date
}
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run start:dev

# Build
npm run build

# Run in production mode
npm run start:prod
```

## Docker

```bash
# Build image
docker build -t uitgo-auth .

# Run container
docker run -p 3000:3000 \
  -e COGNITO_USER_POOL_ID=us-east-1_xxxxx \
  -e COGNITO_CLIENT_ID=xxxxx \
  -e COGNITO_REGION=us-east-1 \
  -e MONGO_URL=mongodb://mongo:27017/uitgo \
  -e JWT_SECRET=your-secret \
  -e AWS_ACCESS_KEY_ID=xxxxx \
  -e AWS_SECRET_ACCESS_KEY=xxxxx \
  uitgo-auth
```

## Health Check

- `GET /healthz` - Health check endpoint
  - Returns: `{ status: "ok" }`

## Error Handling

- **400 Bad Request**: Invalid input (missing email, invalid format)
- **401 Unauthorized**: Invalid credentials, email not verified
- **404 Not Found**: User not found
- **500 Internal Server Error**: Cognito error, database error

## Security Considerations

1. **Password**: Không lưu password trong MongoDB, Cognito handle password hashing
2. **JWT Secret**: Phải match với gateway-service
3. **Email Verification**: Bắt buộc verify email trước khi login
4. **Token Expiration**: Access token có expiration, cần refresh token để renew
5. **Cognito Groups**: Có thể dùng Cognito groups để manage roles (DRIVER, PASSENGER)

## Integration với User Service

Sau khi user register/login thành công, `user-service` cần được gọi để tạo user profile:
- `POST /v1/users` với `{ authId, fullname, role }`

Auth service không tự động tạo user profile, cần client hoặc gateway gọi user-service sau khi register/login.

## Xem thêm

- **Kiến trúc tổng thể**: Xem [`../architecture/README.md`](../architecture/README.md) để hiểu toàn bộ hệ thống UITGo
- **ARCHITECTURE.md**: [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) - Kiến trúc chi tiết
- **REPORT.md**: [`../architecture/REPORT.md`](../architecture/REPORT.md) - Báo cáo Module A

