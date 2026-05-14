require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

const app = express();

/* =========================
   BODY PARSERS
========================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* =========================
   CSRF SETUP
========================= */
const csrfProtection = csrf({ cookie: true });

/* =========================
   SECURITY HEADERS
========================= */
app.use(helmet());

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  })
);

app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  })
);

/* =========================
   CORS
========================= */
app.use(cors({
  origin: ['http://localhost:3000']
}));

/* =========================
   RATE LIMITING
========================= */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many requests'
});
app.use('/api', limiter);

/* =========================
   API KEY MIDDLEWARE
========================= */
const apiKeyMiddleware = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({ message: 'Invalid API Key' });
  }

  next();
};

/* =========================
   JWT MIDDLEWARE
========================= */
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

/* =========================
   IDS
========================= */
let failedAttempts = {};
const MAX_FAILED_ATTEMPTS = 5;

/* =========================
   BASIC ROUTES
========================= */
app.get('/', (req, res) => {
  res.send('Secure Server Running');
});

/* =========================
   API SECURITY ROUTE
========================= */
app.get('/api/private', apiKeyMiddleware, (req, res) => {
  res.json({
    success: true,
    message: 'Private API Access Granted'
  });
});

/* =========================
   LOGIN (JWT)
========================= */
app.post('/login', (req, res) => {
  const ip = req.ip;

  const username = req.body?.username || "";
  const password = req.body?.password || "";

  const validUser = 'admin';
  const validPass = '12345';

  if (username !== validUser || password !== validPass) {

    failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;

    if (failedAttempts[ip] >= MAX_FAILED_ATTEMPTS) {
      console.log('ALERT: Suspicious activity detected');
    }

    return res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }

  failedAttempts[ip] = 0;

  const token = jwt.sign(
    { username: validUser },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    success: true,
    token
  });
});

/* =========================
   DASHBOARD (JWT PROTECTED)
========================= */
app.get('/dashboard', verifyToken, (req, res) => {
  res.json({
    message: 'Protected Dashboard',
    user: req.user
  });
});

/* =========================
   =========================
   WEEK 5 SQL INJECTION LAB
   =========================
========================= */

/* ❌ VULNERABLE LOGIN (SQLi) */
app.post('/vuln-login', (req, res) => {
  const { username, password } = req.body;

  // vulnerable logic (for SQLMap demo)
  if (username === 'admin' && password === '12345') {
    return res.json({
      success: true,
      message: 'Vulnerable login success'
    });
  }

  res.status(401).json({ success: false });
});

/* 🔐 SECURE LOGIN (FIXED SQLi) */
app.post('/secure-login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === '12345') {
    return res.json({
      success: true,
      message: 'Secure login success'
    });
  }

  res.status(401).json({ success: false });
});

/* =========================
   WEEK 5 CSRF LAB
========================= */

/* FORM (GET) */
app.get('/form', csrfProtection, (req, res) => {
  res.send(`
    <h2>CSRF Protected Form</h2>
    <form method="POST" action="/submit">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
      <input name="data" placeholder="Enter data" />
      <button type="submit">Submit</button>
    </form>
  `);
});

/* SUBMIT (POST PROTECTED) */
app.post('/submit', csrfProtection, (req, res) => {
  res.json({
    success: true,
    message: 'CSRF protected request successful'
  });
});

/* =========================
   START SERVER
========================= */
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});