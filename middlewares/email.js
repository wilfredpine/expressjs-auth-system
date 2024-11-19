/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

require('@dotenvx/dotenvx').config()
const nodemailer = require('nodemailer');

/**
 * Email Configuration
 */
const emailConfig = {
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT === '465',                   // true for port 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
};

const transporter = nodemailer.createTransport(emailConfig);

/**
 * Sending Email Function
 * @param {*} to 
 * @param {*} subject 
 * @param {*} text 
 * @param {*} html 
 */
const send_email = async (to, subject, text, html) => {
    try {
        await transporter.sendMail({
            from: emailConfig.auth.user,
            to,
            subject,
            text,
            html
        });
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
        throw error; // or handle the error as needed
    }
};

/**
 * Handle sending email verification link
 * @param {*} userEmail 
 * @param {*} token 
 */
const sendVerificationEmail = async (userEmail, token) => {
    const verifyUrl = `${process.env.BASE_URL || 'http://127.0.0.1:3000/'}auth/verify-email?token=${token}`;
    const subject = 'Email Verification';
    const text = `Please verify your email by clicking on the following link: ${process.env.BASE_URL || 'http://127.0.0.1:3000/'}auth/verify-email?token=${token}`;
    const html = `<p>Please verify your email by clicking on the following link: <a href="${verifyUrl}">Verify Email</a></p>`;

    await send_email(userEmail, subject, text, html);
};

/**
 * handle email sending password reset link
 * @param {*} userEmail 
 * @param {*} token 
 */
const sendPasswordResetEmail = async (userEmail, token) => {
    const resetUrl = `${process.env.BASE_URL || 'http://127.0.0.1:3000/'}auth/new-password?token=${token}`;
    const subject = 'Password Reset';
    const text = `Reset your password by clicking on the following link: ${process.env.BASE_URL || 'http://127.0.0.1:3000/'}auth/new-password?token=${token}`;
    const html = `<p>Reset your password by clicking on the following link: <a href="${resetUrl}">Reset Password</a></p>`;

    await send_email(userEmail, subject, text, html);
};

module.exports = { send_email, sendVerificationEmail, sendPasswordResetEmail };
