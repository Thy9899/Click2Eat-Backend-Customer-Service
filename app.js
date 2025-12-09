require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const connectDB = require("./src/util/db");
const customerRoutes = require("./src/routes/customer.route");
const cors = require("cors");

const app = express();

// Enable CORS
app.use(cors());

// Middleware
app.use(express.json());
app.use(morgan("dev"));

// Connect MongoDB
connectDB();

// Static folder for images
app.use("/Images", express.static("public/Images"));

// Routes
app.use("/api/customers", customerRoutes);

// Start server
const PORT = process.env.PORT || 5002;
app.listen(PORT, () => {
  console.log(`✅ Customer service running on port ${PORT}`);
});
