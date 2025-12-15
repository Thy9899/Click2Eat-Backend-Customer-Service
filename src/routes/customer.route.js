const express = require("express");
const router = express.Router();
const customerController = require("../controller/customer.controller");
const authenticateToken = require("../middleware/authMiddleware");
const authenticateTokenAdmin = require("../middleware/authMiddlewareAdmin");
const multer = require("multer");

// =======================================
// Use memory storage (no physical file created)
// =======================================
const upload = multer({ storage: multer.memoryStorage() });

// =======================================
// CUTOMER REGISTER
// =======================================
router.post("/register", customerController.register);

// =======================================
// CUTOMER LOGIN
// =======================================
router.post("/login", customerController.login);

// =======================================
// PROFILE
// =======================================
router.get("/profile", authenticateToken, customerController.getProfile);

// =======================================
// UPDATE
// =======================================
router.put(
  "/profile/:id",
  authenticateToken,
  upload.single("image"),
  customerController.update
);

// =======================================
// DELETE
// =======================================
router.delete(
  "/profile/:id",
  authenticateToken,
  customerController.deleteProfile
);

// =======================================
// GET ALL (Admin Only)
// =======================================
router.get("/customer", authenticateTokenAdmin, customerController.getAll);

module.exports = router;
