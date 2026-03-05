require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const validator = require("validator");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cors());
app.set("trust proxy", 1); // Trust proxy for rate limiting

/* ================== RATE LIMITING ================== */

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per windowMs
  message: "Too many registration attempts, please try again later"
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per windowMs
  message: "Too many login attempts, please try again later"
});

/* ================== DATABASE ================== */

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error("MongoDB Connection Error:", err));

/* ================== MODELS ================== */

const studentSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    sparse: true,
    index: true
  },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  verificationToken: String,
  verificationTokenExpires: Date,
  registeredEvents: [{ type: mongoose.Schema.Types.ObjectId, ref: "Event" }],
  createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
studentSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (err) {
    next(err);
  }
});

// Method to compare passwords
studentSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const Student = mongoose.model("Student", studentSchema);

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Event = mongoose.model("Event", eventSchema);

/* ================== EMAIL SETUP ================== */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* ================== MIDDLEWARE ================== */

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired" });
    }
    res.status(401).json({ message: "Invalid token" });
  }
};

/* ================== INPUT VALIDATION ================== */

const validateEmail = (email) => {
  return validator.isEmail(email);
};

const validatePassword = (password) => {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special char
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

const validateName = (name) => {
  return name && name.trim().length >= 2 && name.trim().length <= 50;
};

/* ================== ROUTES ================== */

/* ===== REGISTER ===== */

app.post("/student/register", registerLimiter, async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    // Validate inputs
    if (!validateName(name)) {
      return res.status(400).json({ message: "Name must be 2-50 characters" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        message: "Password must be at least 8 characters with uppercase, lowercase, number, and special character"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    // Check if student already exists
    const existingStudent = await Student.findOne({ email: email.toLowerCase() });
    if (existingStudent) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationTokenHash = crypto.createHash("sha256").update(verificationToken).digest("hex");

    const student = await Student.create({
      name: name.trim(),
      email: email.toLowerCase(),
      password,
      verificationToken: verificationTokenHash,
      verificationTokenExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    });

    const verifyLink = `${process.env.FRONTEND_URL}/verify?token=${verificationToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Campus Connect Email Verification",
      html: `
        <h3>Welcome to Campus Connect!</h3>
        <p>Please verify your email to complete registration.</p>
        <p>This link expires in 24 hours.</p>
        <a href="${verifyLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
        <p>Or copy this link: ${verifyLink}</p>
      `
    });

    res.status(201).json({ message: "Registration successful. Check your email to verify." });

  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "Registration failed. Please try again." });
  }
});

/* ===== VERIFY EMAIL ===== */

app.post("/student/verify", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: "Verification token required" });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const student = await Student.findOne({
      verificationToken: tokenHash,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!student) {
      return res.status(400).json({ message: "Invalid or expired verification link" });
    }

    student.verified = true;
    student.verificationToken = undefined;
    student.verificationTokenExpires = undefined;
    await student.save();

    res.json({ message: "Email verified successfully. You can now login." });

  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ message: "Verification failed" });
  }
});

/* ===== LOGIN ===== */

app.post("/student/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate inputs
    if (!validateEmail(email) || !password) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const student = await Student.findOne({ email: email.toLowerCase() });

    if (!student) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!student.verified) {
      return res.status(403).json({ message: "Please verify your email first" });
    }

    const isMatch = await student.comparePassword(password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: student._id, email: student.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      message: "Login successful"
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Login failed. Please try again." });
  }
});

/* ===== DASHBOARD ===== */

app.get("/student/dashboard", authMiddleware, async (req, res) => {
  try {
    const student = await Student.findById(req.user.id)
      .select("-password -verificationToken -verificationTokenExpires")
      .populate("registeredEvents");

    if (!student) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.json(student);

  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ message: "Failed to fetch dashboard" });
  }
});

/* ===== UPDATE PROFILE ===== */

app.put("/student/profile", authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;

    if (!validateName(name)) {
      return res.status(400).json({ message: "Name must be 2-50 characters" });
    }

    const student = await Student.findByIdAndUpdate(
      req.user.id,
      { name: name.trim() },
      { new: true }
    ).select("-password -verificationToken -verificationTokenExpires");

    res.json({ message: "Profile updated successfully", student });

  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

/* ===== VIEW EVENTS ===== */

app.get("/student/events", authMiddleware, async (req, res) => {
  try {
    const events = await Event.find();
    res.json(events);

  } catch (err) {
    console.error("Events fetch error:", err);
    res.status(500).json({ message: "Failed to fetch events" });
  }
});

/* ===== REGISTER EVENT ===== */

app.post("/student/register-event/:eventId", authMiddleware, async (req, res) => {
  try {
    const { eventId } = req.params;

    // Validate eventId format
    if (!mongoose.Types.ObjectId.isValid(eventId)) {
      return res.status(400).json({ message: "Invalid event ID" });
    }

    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    const student = await Student.findById(req.user.id);

    if (student.registeredEvents.includes(eventId)) {
      return res.status(400).json({ message: "Already registered for this event" });
    }

    student.registeredEvents.push(eventId);
    await student.save();

    res.json({ message: "Event registered successfully" });

  } catch (err) {
    console.error("Event registration error:", err);
    res.status(500).json({ message: "Failed to register for event" });
  }
});

/* ===== LOGOUT ===== */

app.post("/student/logout", authMiddleware, (req, res) => {
  // Token is stateless, so logout is handled on client side
  res.json({ message: "Logged out successfully" });
});

/* ===== PASSWORD RESET ===== */

app.post("/student/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email" });
    }

    const student = await Student.findOne({ email: email.toLowerCase() });

    // Don't reveal if email exists
    if (!student) {
      return res.json({ message: "If email exists, reset link will be sent" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");

    student.verificationToken = resetTokenHash;
    student.verificationTokenExpires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour
    await student.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Campus Connect Password Reset",
      html: `
        <h3>Password Reset Request</h3>
        <p>Click the link below to reset your password. This link expires in 1 hour.</p>
        <a href="${resetLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
      `
    });

    res.json({ message: "If email exists, reset link will be sent" });

  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Failed to process request" });
  }
});

/* ================== ERROR HANDLING ================== */

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ message: "Internal server error" });
});

/* ================== START SERVER ================== */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);