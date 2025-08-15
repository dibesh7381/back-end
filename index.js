// server.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();

app.use(cors());

app.use(express.json());

const PORT = process.env.PORT || 5000;

// MongoDB connect
mongoose
  .connect(process.env.MONGO_URI, { dbName: "auth_demo" })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ DB error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: {type : String , required : true},
  email: { type: String, unique: true, required : true },
  password: {type : String , required : true}
},{versionKey : false});
const User = mongoose.model("User", userSchema);

// ===== Signup =====
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "Name, email and password required" });

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "Signup successful" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===== Login =====
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: `Welcome back, ${user.name}`,
      token,
      user: { name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Middleware for profile page :- 
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']; // Authorization: Bearer <token>
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: "Access denied, token missing" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = user; // attach user payload to request object
    next();
  });
}

// Protected profile route
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    // req.user.id contains the user id from token payload
    const user = await User.findById(req.user.id).select('-password'); // don't send password
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// for uptimerobot
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', time: new Date().toISOString() });
});

app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);

