const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Customer = require("../models/customer.model");
const cloudinary = require("../config/cloudinary");

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "7d";
const SALT_ROUNDS = 10;

/**
 * Upload image buffer to Cloudinary
 * @purpose Upload customer profile image
 */
const uploadToCloudinary = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader
      .upload_stream({ folder: "customer_profiles" }, (err, result) => {
        if (err) reject(err);
        else resolve(result.secure_url);
      })
      .end(fileBuffer);
  });
};
/* Explanation:
 • Uploads customer profile images to Cloudinary
 • Stores images inside "customer_profiles" folder
 • Returns secure image URL */

/**
 * Register new customer
 * @route POST /api/customers/register
 * @access Public
 */
const register = async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // 1. Validate input
    if (!email || !username || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // 2. Check if user already exists
    const exists = await Customer.findOne({
      $or: [{ email }, { username }],
    });

    if (exists) {
      return res.status(409).json({ message: "Customer already exists" });
    }

    // 3. Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // 4. Create customer
    const newCustomer = await Customer.create({
      email,
      username,
      password: hashedPassword,
      image: null,
    });

    // 5. Create JWT token
    const token = jwt.sign(
      { id: newCustomer._id, email: newCustomer.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // 6. Send response
    res.status(201).json({
      message: "Registration successful",
      token,
      customer: {
        id: newCustomer._id,
        email: newCustomer.email,
        username: newCustomer.username,
        image: newCustomer.image,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

/* Explanation:
 • Handles customer registration
 • Validates required input fields
 • Hashes password before storing
 • Prevents duplicate email or username */

/**
 * Customer login
 * @route POST /api/customers/login
 * @access Public
 */
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
      },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
/* Explanation:
 • Authenticates customer credentials
 • Compares hashed passwords securely
 • Generates JWT token for authorization
 • Returns customer information and token */

/**
 * Get customer profile
 * @route GET /api/customers/profile
 * @access Customer
 */
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
        createdAt: customer.createdAt,
      },
    });
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
/* Explanation:
 • Retrieves authenticated customer profile
 • Returns personal and profile information
 • Ensures customer exists */

/**
 * Update customer profile
 * @route PUT /api/customers/profile/:id
 * @access Customer
 */
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
      const cloudinaryUrl = await uploadToCloudinary(req.file.buffer);
      customer.image = cloudinaryUrl;
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
      },
    });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
/* Explanation:
 • Updates customer profile information
 • Supports password and image updates
 • Uploads new profile image to Cloudinary */

/**
 * Delete customer profile
 * @route DELETE /api/customers/profile/:id
 * @access Customer
 */
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
/* Explanation:
 • Deletes customer account by ID
 • Ensures customer exists
 • Returns confirmation message */

/**
 * Get all customers
 * @route GET /api/customers
 * @access Admin
 */
const getAll = async (req, res) => {
  try {
    if (!req.user?.is_admin) {
      return res.status(403).json({ error: "Access denied" });
    }

    const list = await Customer.find();
    res.json({ success: true, list });
  } catch (err) {
    console.error("getAll Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
/* Explanation:
 • Retrieves list of all customers
 • Restricted to admin access only
 • Returns customer data */

module.exports = {
  register,
  login,
  getProfile,
  update,
  deleteProfile,
  getAll,
};
