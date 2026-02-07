# Student Authentication Backend

Backend API for Student Exam Portal Authentication System.

## Features
- Register User
- Login with JWT
- Password Hashing
- Forgot Password (Email Reset Link)
- Reset Password with Token Expiry

## Tech Stack
- Node.js
- Express.js
- MongoDB
- JWT
- bcryptjs
- Nodemailer

## Setup

1. Clone repository
git clone https://github.com/Amar-Singh6398/student-auth-backend

2. Install dependencies
npm install

3. Create .env file

MONGO_URI=your_mongo_url  
JWT_SECRET=your_secret  
EMAIL_USER=your_email  
EMAIL_PASS=your_app_password  

4. Start server
npm run dev

Backend runs on:
http://localhost:5000

## Frontend Repository
https://github.com/Amar-Singh6398/student-auth-frontend
