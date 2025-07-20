This backend system is built using Node.js and Express.js to handle user signup, login, OTP verification, and token refresh. It uses JWT for secure session tokens and HTTP-only cookies to store refresh tokens safely.

Let me walk you through how cookies, OTP, and middleware work in this system.

---

### 🔐 HTTP-only Cookies – Keeping Refresh Tokens Safe

After a user successfully verifies their OTP, the system issues two tokens: an **access token** and a **refresh token**.

- The **access token** is short-lived (10 minutes) and is used to access protected routes.
- The **refresh token** is long-lived (7 days) and allows the user to get a new access token without logging in again.

Instead of sending the refresh token in the response body, it’s stored in an **HTTP-only cookie**. This means:
- JavaScript running in the browser **can’t access it**, protecting it from XSS attacks.
- Only the server can read it when needed, like during a token refresh.

This cookie is set with options like `httpOnly`, `maxAge`, and `secure`, making it both safe and persistent.

---

### 📱 OTP – Adding a Layer of Security

Instead of logging a user in directly with just a password, this system uses a **One-Time Password (OTP)** flow to add a layer of security.

Here’s how it works:
1. The user logs in with their email and password.
2. The server generates a 6-digit OTP and stores it in memory with an expiration time (5 minutes).
3. The user must then submit that OTP to the `/verify-otp` endpoint to get their tokens.

The OTP is currently **simulated** — it doesn’t send an actual email or SMS, but it logs the OTP to the console so you can copy and use it for testing.

This approach makes the system easy to test locally while keeping the structure ready for real-world use with minimal changes.

---

### 🛡️ Middleware – Protecting Routes

Middleware in Express runs before a request reaches the route handler. I used a simple but effective middleware called `authMiddleware` to protect routes like `/protected`.

Here’s what it does:
- It checks for an `Authorization` header with a Bearer token.
- It verifies the JWT using the secret key.
- If the token is valid, it lets the request continue.
- If not, it returns a `401 Unauthorized`.

This ensures that only authenticated users with a valid access token can access protected parts of the API.

---

### 🔄 Token Refresh – Keeping the Session Alive

Since access tokens expire after 10 minutes, users can't stay logged in forever just with that. So, the **refresh token** stored in the cookie comes into play.

When the access token expires, the user can call `/refresh-token`, and the server:
- Reads the refresh token from the cookie
- Verifies it
- Issues a new access token if valid

This way, the user stays logged in securely without having to enter their password again every 10 minutes.

---

### 🗂️ In-Memory Storage – Simple and Lightweight

For simplicity and ease of setup, this app uses JavaScript objects to store:
- Users
- OTPs
- Refresh tokens

This makes the system lightweight and perfect for development or demonstration purposes. In a real production app, these would be stored in a database like MongoDB or PostgreSQL.

---

### 🧪 Final Flow Summary

1. **Signup** – User creates an account with name, email, mobile, and password.
2. **Login** – User logs in with email and password. OTP is generated.
3. **Verify OTP** – User submits OTP to get access and refresh tokens.
4. **Access Protected Route** – Use the access token to access secure routes.
5. **Refresh Token** – When access token expires, use the refresh token (from cookie) to get a new one.

---

This system is a solid foundation for secure user authentication using modern practices like JWT, OTP, and HTTP-only cookies. It’s simple enough to understand and extend, making it a great example of a secure Node.js backend.
