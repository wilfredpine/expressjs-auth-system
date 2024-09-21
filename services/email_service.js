/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

require('dotenv').config();

const nodemailer = require('nodemailer');
const emailConfig = require('../config/email_config');

const transporter = nodemailer.createTransport(emailConfig);

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

const sendVerificationEmail = async (userEmail, token) => {
    const verifyUrl = `http://127.0.0.1:3000/auth/verify-email?token=${token}`;
    const subject = 'Email Verification';
    const text = `Please verify your email by clicking on the following link: http://127.0.0.1:3000/auth/verify-email?token=${token}`;
    const html = `<p>Please verify your email by clicking on the following link: <a href="${verifyUrl}">Verify Email</a></p>`;

    await send_email(userEmail, subject, text, html);
};

const sendPasswordResetEmail = async (userEmail, token) => {
    const resetUrl = `http://127.0.0.1:3000/auth/new-password?token=${token}`;
    const subject = 'Password Reset';
    const text = `Reset your password by clicking on the following link: http://127.0.0.1:3000/auth/new-password?token=${token}`;
    const html = `<p>Reset your password by clicking on the following link: <a href="${resetUrl}">Reset Password</a></p>`;

    await send_email(userEmail, subject, text, html);
};

module.exports = { send_email, sendVerificationEmail, sendPasswordResetEmail };
