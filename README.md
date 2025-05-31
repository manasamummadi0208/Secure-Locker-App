                                                                              **Secure-Locker-App**
Secure Locker App is a web-based application developed as a final project for SWE 681 – Software Engineering at George Mason University. The application allows users to securely store, manage, and access their files or data in a protected locker after authentication. 
**Problem Statement**
Traditional password-only systems are vulnerable to breaches, especially when users create weak passwords. Without added verification, stolen credentials lead directly to unauthorized access.
**Solution -**
SECURE LOCKER APP
Enforces strong password rules.
Securely hashes and salts password
Implements Two Factor authentication using Google Authenticator
Consists of Admin Panel for user management
**Key Features**
Password strength validation (live checklist).
Secure password hashing using PBKDF2 + SHA-256 + random salt with 200k
iterations
2FA integration via google authenticator app.
QR code generation for 2FA setup.
Separate User and Admin login systems.
User search and delete functionality for Admin.
**Technologies Used**
Flask – Web framework for building the backend in Python
SQLite – Lightweight relational database for local storage
PyOTP – Python library for generating and verifying One-Time Passwords (OTP)
qrcode – Library used to generate QR codes for OTP-based two-factor authentication
HTML / CSS / Bootstrap – For responsive and user-friendly frontend design
PBKDF2 Encryption Algorithm – Used to securely hash and store user passwords
