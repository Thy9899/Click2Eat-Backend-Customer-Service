const express = require("express");
const router = express.Router();
const customerController = require("../controller/customer.controller");
const authenticateToken = require("../middleware/authMiddleware");
const authenticateTokenAdmin = require("../middleware/authMiddlewareAdmin");
const multer = require("multer");
// const path = require("path");
// const fs = require("fs");

// Ensure upload folder exists
// const uploadDir = "./public/Images";
// if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// const storage = multer.diskStorage({
//   destination: (req, file, cb) => cb(null, uploadDir),
//   filename: (req, file, cb) => {
//     const ext = path.extname(file.originalname);
//     cb(null, Date.now() + "-" + file.fieldname + ext);
//   },
// });

// const upload = multer({ storage });

const upload = multer({ storage: multer.memoryStorage() });

// AUTH
router.post("/register", customerController.register);
router.post("/login", customerController.login);

// PROFILE
router.get("/profile", authenticateToken, customerController.getProfile);

// UPDATE
router.put(
  "/profile/:id",
  authenticateToken,
  upload.single("image"),
  customerController.update
);

// DELETE
router.delete(
  "/profile/:id",
  authenticateToken,
  customerController.deleteProfile
);

router.get("/customer", authenticateTokenAdmin, customerController.getAll);

module.exports = router;
