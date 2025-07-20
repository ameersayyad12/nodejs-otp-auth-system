
Backend System Assignment Explanation

This backend system is built using Node.js and Express.js to provide secure user signup and login functionality with OTP and JWT-based authentication.

**Cookies**
- The backend uses HTTP-only cookies to store the refresh token after successful OTP verification.
- HTTP-only cookies are not accessible via client-side JavaScript, which helps protect against XSS attacks.
- When the client requests a new access token via `/refresh-token`, the server reads the refresh token from the cookie, verifies it, and issues a new access token.

**OTP (One-Time Password)**
- On login, the backend generates a random 6-digit OTP and stores it in memory with an expiry time (5 minutes).
- The OTP is sent to the user (simulated by logging to the console).
- The user submits the OTP and its ID to `/verify-otp`. The backend checks if the OTP matches and is not expired, then deletes it from memory to prevent reuse.

**Middleware**
- The backend uses an authentication middleware (`authMiddleware`) to protect sensitive routes.
- The middleware checks for a valid JWT access token in theAuthorization` header (`Bearer <token>`).
- If the token is valid, the request proceeds; otherwise, the server responds with `401 Unauthorized`.
- This ensures only authenticated users can access protected endpoints.

**Storage**
- User data and OTPs are stored in memory for simplicity, as allowed by the assignment.
- Passwords are securely hashed using bcrypt before storage.

**Summary**
- The backend fulfills all assignment requirements: in-memory storage, OTP logic, secure cookies, and route protection via middleware.
- All endpoints are tested and working as expected.
