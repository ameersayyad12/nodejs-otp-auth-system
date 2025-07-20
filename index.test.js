const request = require('supertest');
const { app, otpStore } = require('./index');
let otpId;
let otp;
let accessToken;

describe('Backend System API', () => {
  it('should signup a new user', async () => {
    const res = await request(app)
      .post('/signup')
      .send({
        name: 'Test User',
        email: 'test@example.com',
        mobile: '1234567890',
        password: 'password123'
      });
    expect(res.statusCode).toBe(201);
    expect(res.body.message).toBe('User created successfully');
  });

  it('should login and receive OTP', async () => {
    const res = await request(app)
      .post('/login')
      .send({
        email: 'test@example.com',
        password: 'password123'
      });
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe('OTP sent');
    expect(res.body.otpId).toBeDefined();
    otpId = res.body.otpId;

    // Access OTP value from in-memory store for testing purposes
    const { otpStore } = require('./index');
    otp = otpStore[otpId].otp;
    expect(otp).toBeDefined();
  });

  it('should verify OTP and receive access token', async () => {
    const res = await request(app)
      .post('/verify-otp')
      .send({
        otpId,
        otp
      });
    expect(res.statusCode).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    accessToken = res.body.accessToken;
  });

  it('should access protected route with valid token', async () => {
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe('You are authorized!');
    expect(res.body.user).toBeDefined();
  });

  it('should not access protected route with invalid token', async () => {
    const res = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer invalidtoken');
    expect(res.statusCode).toBe(401);
    expect(res.body.message).toMatch(/Invalid token|Missing or invalid token/);
  });
});