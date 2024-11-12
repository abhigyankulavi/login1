// frontend/src/App.jsx
import React, { useState } from 'react';
import './App.css';

function App() {
  const [userType, setUserType] = useState('patient');
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    remember: false
  });
  const [message, setMessage] = useState({ type: '', content: '' });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...formData, userType })
      });
      const data = await response.json();
      
      if (!response.ok) throw new Error(data.message);
      
      setMessage({ type: 'success', content: 'Login successful! Redirecting...' });
      localStorage.setItem('token', data.token);
      setTimeout(() => {
        window.location.href = `/${userType}_dashboard`;
      }, 1500);
    } catch (error) {
      setMessage({ type: 'error', content: error.message });
    }
  };

  const handleForgotPassword = async () => {
    if (!formData.email) {
      setMessage({ type: 'error', content: 'Please enter your email address' });
      return;
    }
    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: formData.email })
      });
      const data = await response.json();
      
      if (!response.ok) throw new Error(data.message);
      
      setMessage({ type: 'success', content: 'Password reset email sent!' });
    } catch (error) {
      setMessage({ type: 'error', content: error.message });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-white flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white p-8 rounded-lg shadow-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-blue-800">E-Health Advisor</h1>
          <p className="text-gray-600">Welcome back! Please login to continue.</p>
        </div>

        {message.content && (
          <div className={`text-center mb-4 text-sm ${
            message.type === 'error' ? 'text-red-600' : 'text-green-600'
          }`}>
            {message.content}
          </div>
        )}

        <div className="flex bg-gray-100 rounded-md p-1 mb-8">
          <button
            className={`flex-1 py-2 rounded-md transition ${
              userType === 'patient'
                ? 'bg-white text-blue-600 shadow'
                : 'text-gray-600'
            }`}
            onClick={() => setUserType('patient')}
          >
            Patient
          </button>
          <button
            className={`flex-1 py-2 rounded-md transition ${
              userType === 'admin'
                ? 'bg-white text-blue-600 shadow'
                : 'text-gray-600'
            }`}
            onClick={() => setUserType('admin')}
          >
            Admin
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <div className="relative">
              <input
                type="email"
                className="w-full px-10 py-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter your email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                required
              />
              <span className="absolute left-3 top-1/2 -translate-y-1/2">📧</span>
            </div>
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <div className="relative">
              <input
                type="password"
                className="w-full px-10 py-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter your password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                required
              />
              <span className="absolute left-3 top-1/2 -translate-y-1/2">🔒</span>
            </div>
          </div>

          <div className="flex justify-between items-center mb-6">
            <label className="flex items-center">
              <input
                type="checkbox"
                className="w-4 h-4 text-blue-600"
                checked={formData.remember}
                onChange={(e) => setFormData({ ...formData, remember: e.target.checked })}
              />
              <span className="ml-2 text-sm text-gray-600">Remember me</span>
            </label>
            <button
              type="button"
              onClick={handleForgotPassword}
              className="text-sm text-blue-600 hover:underline"
            >
              Forgot password?
            </button>
          </div>

          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 transition"
          >
            Sign in
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;

// backend/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  userType: {
    type: String,
    enum: ['patient', 'admin'],
    required: true,
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);

// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const User = require('./models/User');

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend/build')));

mongoose.connect(process.env.MONGODB_URI);

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, userType } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await user.comparePassword(password)) || user.userType !== userType) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const token = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset',
      text: `You are receiving this because you requested a password reset.
      Please click on the following link to complete the process:
      ${process.env.FRONTEND_URL}/reset-password/${token}`
    });

    res.json({ message: 'Reset email sent' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// .env
MONGODB_URI=your_mongodb_uri
JWT_SECRET=your_jwt_secret
EMAIL_USER=your_gmail_address
EMAIL_PASS=your_gmail_app_password
FRONTEND_URL=https://your-app.onrender.com
