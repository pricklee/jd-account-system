const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const machineId = require("node-machine-id");
const crypto = require('crypto');
const os = require('os');
const { execSync } = require('child_process');
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

  const bannedWords = ["nigger", "ass", "nigga", "niga", "nig", "niger", "fuck", "fag", "fagget", "boob", "dick", "bastard", "faggot", "retard", "penis", "slut", "tit", "tits", "fucker", "nazi", "isis", "sex", "rape", "porn", "pornhub", "xnxx", "xvideos", "xhamsters", "pussy", "vagina", "r34", "rule34", "genocide", "trany", "tranny", "tranni", "trani", "f@g", "r@pe", "b00b", "misticalkai", "pricklety", "jammerdash", "automoderator", "hizuru_chan", "hizuru", "n-word", "k-word", "kike", "chink", "ch1nk", "ch!nk", "dyke", "shemale", "she-male", "shemale", "she-male", "p0rn", "porno", "p0rno", "anus", "genitals", "cock", "cocks", "c0ck", "c0cks"]

  const containsProfanity = (text) => {
      const lowerCaseText = text.toLowerCase();
      return bannedWords.some((word) => lowerCaseText.includes(word));
  };

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
    canEditOtherAccounts: false,
    canSuspendAccounts: true,
    canApproveMaps: true,
    canEditMaps: true,
    canEditRoles: false,
    canAccessAdminDashboard: false,
  },
  bot: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: true,
  },
  supporter: {
    canEditOwnAccount: true,
    canEditOtherAccounts: false,
    canSuspendAccounts: false,
    canEditRoles: false,
    canApproveMaps: false,
    canEditMaps: false,
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
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.log("Authorization token missing");
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const banCheck = await pool.query(
      "SELECT * FROM hardware_bans WHERE hardware_id = $1",
      [hardware_id]
    );

    if (banCheck.rows.length > 0) {
      console.log("Blocked login attempt from banned hardware:", hardware_id);
      return res.status(403).json({ error: "This account has been banned" });
    }
  } catch (error) {
    console.error("Error checking hardware bans:", error);
    return res.status(500).json({ error: "Server error" });
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

// Middleware: Authentication with Public Preview Bypass
const authMiddleware = (req, res, next) => {
  if (process.env.ALLOW_PUBLIC_PREVIEW === "true" && req.headers["x-env"] === "preview") {
    return next(); // Bypass authentication
  }
  // Regular authentication logic here
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
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

const getHardwareID = async () => {
  try {
    // Get system info
    const networkInterfaces = os.networkInterfaces();
    const cpuInfo = os.cpus()[0].model;
    
    // Get MAC address
    const macs = Object.values(networkInterfaces)
      .flat()
      .filter(iface => !iface.internal && iface.mac !== '00:00:00:00:00:00')
      .map(iface => iface.mac)
      .join('');

    // Get disk serial (Windows & Linux specific)
    let diskSerial = '';
    if (process.platform === 'win32') {
      try {
        diskSerial = execSync('wmic diskdrive get SerialNumber').toString().trim();
      } catch (err) {
        console.error('Error getting disk serial for your Windows device:', err);
      }
    } else if (process.platform === 'linux') {
      try {
        diskSerial = execSync('cat /sys/class/dmi/id/product_uuid').toString().trim();
      } catch (err) {
        console.error('Error getting disk serial for your Linux device:', err);
      }
    } else {
      console.error('Unsupported platform:', process.platform);
    }

    // Combine hardware identifiers
    const hardwareString = `${macs}${cpuInfo}${diskSerial}${os.hostname()}`;
    
    // Create SHA-256 hash
    const hardwareHash = crypto
      .createHash('sha256')
      .update(hardwareString)
      .digest('hex');

    console.log('Generated Hardware ID:', hardwareHash);
    return hardwareHash;

  } catch (error) {
    console.error("Error generating hardware ID:", error);
    return null;
  }
};

// Validate UUID format
function validateUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// Routes
// Login endpoint - uses username/password
app.post("/v1/account/login", async (req, res) => {
  console.log("Login attempt - Request body:", req.body);

  const { username, password } = req.body;
  let hardware_id;

  if (!username || !password ) {
    console.log("Missing username or password");
    return res.status(400).json({
      error: "Username and password required",
    });
  }

  try {
    hardware_id = await getHardwareID();
    console.log("Hardware ID:", hardware_id);
    if (!hardware_id) {
      return res.status(400).json({ error: "Hardware ID could not be found" });
    }
  } catch (error) {
    console.error("Error getting hardware ID:", error);
    return res.status(500).json({ error: "Server Error" });
  }

  try {
  const banCheck = await pool.query(
    "SELECT * FROM hardware_bans WHERE hardware_id = $1",
    [hardware_id]
  )

  if (banCheck.rows.length > 0) {
      console.log("Blocked login attempt from banned hardware:", hardware_id);
      return res.status(403).json({ error: "This hardware has been banned" });
  }

    console.log("Querying for user:", username);
    const userQuery = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    console.log("User query result:", userQuery.rows);

 if (userQuery.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userQuery.rows[0];
    let hashedPassword = password;

    if (password.length !== 64) {
      hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    }

    const isMatch = await bcrypt.compare(hashedPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    if (user.is_suspended) {
      console.log("Login attempt from a suspended account:", username);
      return res.status(403).json({ error: "This account has been suspended, you may not login" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role_perms: user.role_perms,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.status(200).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role_perms: user.role_perms,
        is_staff: user.is_staff,
        hardware_id: user.hardware_id,
      },
    });

await pool.query(
  "UPDATE users SET hardware_id = $1 WHERE id = $2",
  [hardware_id, username]
);

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ error: "Server error" });
  }
});

// Signup
app.post("/v1/account/signup", async (req, res) => {
  const { nickname, username, email, password } = req.body;

  // Check if all required fields are provided
  if (!nickname || !username || !email || !password) {
    console.error(`Sign-up failed: Missing required fields. Request body: ${JSON.stringify(req.body)}`);
    return res.status(400).json({ error: "All fields are required" });
  }

  // Validates username format
  const usernameRegex = /^[a-z0-9_]+$/;
  if (!usernameRegex.test(username)) {
    console.error(`Sign-up failed: Account username must only contain lowercase letters, numbers, and underscores: ${username}`);
    return res.status(400).json({ error: "Username must only contain lowercase letters, numbers, and underscores, spaces are not allowed" });
  }

  if (containsProfanity(username) || containsProfanity(nickname)) {
    console.error(`Sign-up failed: Username or nickname contains a banned word: ${username}, ${nickname}`);
    return res.status(400).json({ error: "Username or nickname contains a banned word" });
  }

  try {
    // Check if the username or email already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );

  const MAX_USERNAME_LENGTH = 20;
  if (username.length > MAX_USERNAME_LENGTH) {
    console.error(`Sign-up failed: Username exceeds maximum length: ${username}`);
    return res.status(400).json({ error: `Username must be ${MAX_USERNAME_LENGTH} characters or less`});
  }

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username or email already exists" });
    }

    let hashedPassword = password;
    if (password.length !== 64) {
      hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    }

    const salt = await bcrypt.genSalt(10);
    const bcryptHashedPassword = await bcrypt.hash(password, salt);

    // Insert the new user into the database
    const result = await pool.query(
      "INSERT INTO users (nickname, username, email, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [nickname, username, email, bcryptHashedPassword]
    );

    const newUser = result.rows[0];
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
    const user = await pool.query(
      "SELECT hardware_id FROM users WHERE id = $1",
      [userId]
    );

    if (!user.rows[0]) {
      return res.status(404).json({ error: "User not found" });
    }

    await pool.query(
      "INSERT INTO hardware_bans (hardware_id, reason) VALUES ($1, $2)",
      [user.rows[0].hardware_id, reason]
    );

    await pool.query(
      "UPDATE users SET is_suspended = true WHERE id = $1",
      [userId]
    )

    console.log(`user ${userId} has been suspended`);
    res.status(200).json({ message: `User ${userId} has been suspended` });
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
  const { nickname, username, email } = req.body;

  if (!nickname || !username || !email) {
    console.error("Editing ${username} failed: Missing required fields.");
    return res.status(400).json({ error: "Nickname, Username, and Email are required for edit" });
  }

  const canEditOwnAccount = rolePermissions[req.user.role_perms]?.canEditOwnAccount;
  const canEditOtherAccounts = rolePermissions[req.user.role_perms]?.canEditOtherAccounts;

  if (req.user.id !== userId && !canEditOtherAccounts) {
    console.error(`User ${req.user.username} does not have permission to edit another account`);
    return res.status(403).json({ error: "Access denied" });
  }

  if (req.user.id === userId && !canEditOwnAccount) {
    console.error(`User ${req.user.username} does not have permission to edit their own account`);
    return res.status(403).json({ error: "Access denied" });
  }

  try {
    const existingUser = await pool.query(
      "SELECT * FROM user WHERE (email = $1 OR username = $2) AND id != $3",
      [email, username, userId]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username or email already exists" });
    }

    await pool.query(
      "UPDATE users SET nickname = $1, username = $2, email = $3 WHERE id = $4",
      [nickname, username, email, userId]
    );

    console.log(`User ${userId} updated there account info successfully`);
    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error("Error updating user:", error);
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

// Get user info endpoint - uses UUID
app.get("/v1/account/:id", async (req, res) => {
  const userId = req.params.id;

  if (!validateUUID(userId)) {
    console.log("Invalid UUID format for user ID:", userId);
    return res.status(400).json({ error: "Invalid user ID format" });
  }

  try {
    const result = await pool.query(
      "SELECT id, nickname, username, role_perms, is_staff, is_suspended FROM users WHERE id = $1",
      [userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(result.rows[0]);

  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get user stats enpoint - uses UUID
app.get("/v1/account/:id/stats", async (req, res) => {
  try {
    // Logic coming soon
  } catch (error) {
    console.error("Error fetching user stats:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Edit user stats enpoint - uses UUID - only for the game to edit stats
app.get("/v1/account/:id/stats/edit-stats", async (req, res) => {
  try {
    // Logic coming soon
  } catch (error) {
    console.error("Error editing user stats:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
