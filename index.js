const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 5000;

app.post("/signup", async (req, res) => {
    try {
      const { name, email, password } = req.body;
  
      // Check if user exists
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) return res.status(400).json({ error: "User already exists" });
  
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create user
      const user = await prisma.user.create({
        data: { name, email, password: hashedPassword },
      });
  
      res.json({ message: "User created", user });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;
  
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) return res.status(400).json({ error: "Invalid credentials" });
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });
  
      // Create JWT token
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  
      // Optional: store session in DB
      await prisma.session.create({
        data: { userId: user.id, token, expiresAt: new Date(Date.now() + 3600000) }
      });
  
      res.json({ message: "Login successful", token });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
  