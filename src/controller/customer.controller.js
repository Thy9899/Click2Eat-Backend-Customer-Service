const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Customer = require("../models/customer.model");

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "7d";
const SALT_ROUNDS = 10;

// REGISTER
const register = async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user exists
    const exists = await Customer.findOne({
      $or: [{ email }, { username }],
    });
    if (exists) {
      return res.status(409).json({ message: "Customer already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Save user
    const newCustomer = await Customer.create({
      email,
      username,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "Customer registered successfully",
      customer: {
        customer_id: newCustomer._id,
        email: newCustomer.email,
        username: newCustomer.username,
        createdAt: newCustomer.createdAt,
      },
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

// LOGIN
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const customer = await Customer.findOne({ email });
    if (!customer)
      return res.status(401).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, customer.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      {
        customer_id: customer._id,
        email: customer.email,
        username: customer.username,
        phone: customer.phone,

        image: customer.image,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      message: "Login successful",
      customer: {
        customer_id: customer._id,
        email: customer.email,
        username: customer.username,
        phone: customer.phone,
        image: customer.image,
        // ? `http://localhost:5002/Images/${customer.image}`
        // : null,
      },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

// GET PROFILE
const getProfile = async (req, res) => {
  try {
    const customer = await Customer.findById(req.customer.customer_id).select(
      "email username phone image createdAt"
    );
    if (!customer)
      return res.status(404).json({ message: "Customer not found" });

    res.json({
      customer: {
        customer_id: customer._id,
        email: customer.email,
        username: customer.username,
        phone: customer.phone,
        image: customer.image,
        // ? `http://localhost:5004/Images/${customer.image}`
        // : null,
        createdAt: customer.createdAt,
      },
    });
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

// UPDATE PROFILE
const update = async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, phone, password } = req.body;

    const customer = await Customer.findById(id);
    if (!customer)
      return res.status(404).json({ message: "Customer not found" });

    if (password) customer.password = await bcrypt.hash(password, SALT_ROUNDS);
    if (username) customer.username = username;
    if (email) customer.email = email;
    if (phone) customer.phone = phone;
    if (req.file) {
      customer.image = req.file.filename; // Store only filename
    }

    await customer.save();

    res.json({
      message: "Profile updated successfully",
      customer: {
        customer_id: customer._id,
        email: customer.email,
        username: customer.username,
        phone: customer.phone,
        image: customer.image,
        // ? `http://localhost:5004/Images/${customer.image}`
        // : null,
      },
    });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

//DELETE PROFILE
const deleteProfile = async (req, res) => {
  try {
    const { id } = req.params;

    const customer = await Customer.findByIdAndDelete(id);
    if (!customer)
      return res.status(404).json({ message: "Customer not found" });

    res.json({ message: "Profile deleted successfully" });
  } catch (err) {
    console.error("Delete profile error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = { register, login, getProfile, update, deleteProfile };
