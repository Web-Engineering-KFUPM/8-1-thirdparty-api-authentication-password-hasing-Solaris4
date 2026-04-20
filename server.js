/**
 * =========================================================
 * Lab: SECURE WEATHER DASHBOARD
 * =========================================================
 */

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const JWT_SECRET = "abc123";

app.use(express.json());

// In-memory "database"
let users = [];

// Simple health check
app.get("/", (_req, res) => {
  res.send("Server is running");
});

// =========================
// POST /register
// =========================
app.post("/register", async (req, res) => {
  try {
    // 1) Read JSON body
    const { email, password } = req.body || {};

    // 2) Validate required fields
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // 3) Check if user already exists
    const existing = users.find((u) => u.email === email);
    if (existing) {
      return res.status(400).json({ error: "User already exists" });
    }

    // 4) Hash the password
    const hash = await bcrypt.hash(password, 10);

    // 5) Store the new user
    users.push({ email, passwordHash: hash });

    // 6) Send success response
    return res.status(201).json({ message: "User registered!" });

  } catch (err) {
    // 7) Handle unexpected errors
    console.error("Register error:", err);
    return res.status(500).json({ error: "Server error during register" });
  }
});

// =========================
// POST /login
// =========================
app.post("/login", async (req, res) => {
  try {
    // 1) Read JSON body
    const { email, password } = req.body || {};

    // 2) Validate required fields
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // 3) Find user by email
    const user = users.find((u) => u.email === email);
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    // 4) Compare passwords with bcrypt
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(400).json({ error: "Wrong password" });
    }

    // 5) Create JWT token
    const token = jwt.sign(
      { email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // 6) Return the token
    return res.json({ token });

  } catch (err) {
    // 7) Handle unexpected errors
    console.error("Login error:", err);
    return res.status(500).json({ error: "Server error during login" });
  }
});

// =========================
// Protected Weather API
// GET /weather?city=Riyadh
// =========================
app.get("/weather", async (req, res) => {
  try {
    // 1) Read Authorization header
    const auth = req.headers.authorization;
    if (!auth) {
      return res.status(401).json({ error: "Missing token" });
    }

    // 2) Extract token (format: "Bearer <token>")
    const token = auth.split(" ")[1];

    // 3) Verify token
    try {
      jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }

    // 4) Read city from query string
    const city = req.query.city;
    if (!city) {
      return res.status(400).json({ error: "City required" });
    }

    // 5) Prepare external weather API URL
    const url = `https://wttr.in/${encodeURIComponent(city)}?format=j1`;

    // 6) Call the weather API
    const weatherResponse = await fetch(url);
    if (!weatherResponse.ok) {
      return res.status(500).json({ error: "Error from weather API" });
    }

    // 7) Parse JSON response
    const data = await weatherResponse.json();

    // 8) Return structured weather data
    return res.json({
      city,
      temp: data.temperature,
      description: data.description,
      wind: data.wind,
      raw: data
    });

  } catch (err) {
    // 9) Handle unexpected errors
    console.error("Weather error:", err);
    return res.status(500).json({ error: "Server error during weather fetch" });
  }
});

// Start server
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);