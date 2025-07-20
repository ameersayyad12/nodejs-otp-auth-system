// Simulated OTP logic
function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendOtp(email, otp) {
    console.log(`OTP for ${email}: ${otp}`);
    // Simulate sending via email or SMS
}

module.exports = { generateOtp, sendOtp };