const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// Postgres Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Role Permissions Configuration
const rolePermissions = {
  jd_super_admin: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: true,
  },
  jd_admin: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: false,
  },
  jd_moderator: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canApproveMaps: true,
    canEditMaps: true,
    canEditRoles: false,
    canAccessAdminDashboard: false,
  },
  player: {
    canEditOwnAccount: true,
    canEditOtherAccounts: false,
    canSuspendAccounts: false,
    canEditRoles: false,
    canApproveMaps: false,
    canEditMaps: false,
    canAccessAdminDashboard: false,
  },
};

// Middleware: Authenticate User
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.log("Authorization token missing");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    console.log("Authenticated user:", req.user);
    next();
  } catch (error) {
    console.error("JWT verification failed:", error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: "Token expired" });
    }
    res.status(403).json({ error: "Invalid token" });
  }
};

// Middleware: Check Permission
const checkPermission = (requiredPermission) => {
  return (req, res, next) => {
    const userRole = req.user.role_perms;
    const permissions = rolePermissions[userRole];

    if (!permissions) {
      return res.status(403).json({ error: "Role permissions not found" });
    }

    if (permissions[requiredPermission]) {
      return next();
    }
    console.log(`User ${req.user.username} does not have permission for ${requiredPermission}`);
    return res.status(403).json({ error: "Access denied" });
  };
};

// Routes
// Login
app.post("/v1/account/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role_perms: user.role_perms },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Signup
app.post("/v1/account/signup", async (req, res) => {
  const { nickname, username, email, password } = req.body;

  try {
    // Check if the username or email already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username or email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (nickname, username, email, password) VALUES ($1, $2, $3, $4)",
      [nickname, username, email, hashedPassword]
    );

    res.status(201).json({ message: "Account created" });
  } catch (error) {
    console.error("Error during signup:", error);
    if (error.code === '23505') {  // Unique violation error code in Postgres
      return res.status(400).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Server error" });
  }
});

// Suspend/Unsuspend
app.post("/v1/account/:id/suspend", authenticate, checkPermission("canSuspendAccounts"), async (req, res) => {
  const userId = req.params.id;
  const { action } = req.body;

  try {
    const isSuspended = action === "suspend";
    await pool.query("UPDATE users SET is_suspended = $1 WHERE id = $2", [isSuspended, userId]);

    res.status(200).json({ message: `User ${action}ed successfully` });
  } catch (error) {
    console.error("Error during suspend/unsuspend:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Edit User
app.post("/v1/account/:id/edit-user", authenticate, async (req, res) => {
  const userId = req.params.id;
  const updates = req.body;

  try {
    const user = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
    if (!user.rows.length) return res.status(404).json({ error: "User not found" });

    if (req.user.id !== userId && !rolePermissions[req.user.role_perms].canEditOtherAccounts) {
      return res.status(403).json({ error: "Access denied" });
    }

    const fields = Object.keys(updates).map((key, i) => `${key} = $${i + 1}`).join(", ");
    const values = Object.values(updates);
    values.push(userId);

    await pool.query(`UPDATE users SET ${fields} WHERE id = $${values.length}`, values);

    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error during edit user:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Edit User Role
app.post("/v1/account/:id/edit-user-role", authenticate, checkPermission("canEditRoles"), async (req, res) => {
  const userId = req.params.id;
  const { role_perms } = req.body;

  try {
    if (!rolePermissions[role_perms]) {
      return res.status(400).json({ error: "Invalid role permissions" });
    }

    await pool.query("UPDATE users SET role_perms = $1 WHERE id = $2", [role_perms, userId]);
    res.status(200).json({ message: "Role updated successfully" });
  } catch (error) {
    console.error("Error during edit user role:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get User Info
app.get("/v1/account/:id", authenticate, async (req, res) => {
  const userId = req.params.id;

  try {
    const result = await pool.query("SELECT id, nickname, username, email, role_perms, is_staff, is_suspended FROM users WHERE id = $1", [userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user info:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
