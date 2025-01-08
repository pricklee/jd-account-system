const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const os = require('os');
const axios = require('axios');
const { execSync } = require('child_process');
require("dotenv").config();
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());

// Email configuration 
const transporter = nodemailer.createTransport({
  host: "smtp.zoho.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.ZOHO_EMAIL,
    pass: process.env.ZOHO_PASSWORD,
  },
});
// Trust proxy settings
app.set('trust proxy', true);

// IP Logging
app.use((req, res, next) => {
  req.clientIp = (
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown'
  ).replace(/^::ffff:/, '');

  // Debug logging
  console.log('IP Debug:', {
    connectionIp: req.connection?.remoteAddress,
    socketIp: req.socket?.remoteAddress,
    expressIp: req.ip,
    finalIp: req.clientIp
  });

  next();
});

// Postgres Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

  const bannedWords = ["nigger", "ass", "nigga", "niga", "nig", "niger", "fuck", "fag", "fagget", "boob", "dick", "bastard", "faggot", "retard", "penis", "slut", "tit", "tits", "fucker", "nazi", "isis", "sex", "rape", "porn", "pornhub", "xnxx", "xvideos", "xhamsters", "pussy", "vagina", "r34", "rule34", "genocide", "trany", "tr@nny", "tr@nni", "donaldtrump", "tranny", "tranni", "trani", "f@g", "r@pe", "b00b", "misticalkai", "pricklety", "jammerdash", "automoderator", "hizuru_chan", "hizuru", "n-word", "k-word", "kike", "chink", "ch1nk", "ch!nk", "dyke", "shemale", "she-male", "shemale", "she-male", "p0rn", "porno", "p0rno", "anus", "genitals", "cock", "cocks", "c0ck", "c0cks", "bitch", "b!tch", "cunt"]

  const allowedEmailDomains = ["gmail.com", "jammerdash.com", "misticalkai.com", "outlook.com", "hotmail.com", "msn.com", "aol.com", "protonmail.com", "nijika.dev", "live.com", "yahoo.com", "icloud.com", "zoho.com", "mail.com", "yandex.com", "yandex.ru", "gmx.com", "fastmail.com"]

  const containsProfanity = (text) => {
      const lowerCaseText = text.toLowerCase();
      return bannedWords.some((word) => lowerCaseText.includes(word));
  };

  const isAllowedEmailDOmain = (email) => {
    const domain = email.split('@')[1];
    return allowedEmailDomains.includes(domain);
  }

// Role Permissions Configuration
const rolePermissions = {
  developer: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: true,
  },
  jd_manager: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: true,
  },
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
  community_staff: {
    canEditOwnAccount: true,
    canEditOtherAccounts: false,
    canSuspendAccounts: true,
    canApproveMaps: true,
    canEditMaps: true,
    canEditRoles: false,
    canAccessAdminDashboard: false,
  },
  jammer: {
    canEditOwnAccount: true,
    canEditOtherAccounts: false,
    canSuspendAccounts: false,
    canEditRoles: false,
    canApproveMaps: false,
    canEditMaps: false,
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
  artist: {
    canEditOwnAccount: true,
    canEditOtherAccounts: false,
    canSuspendAccounts: false,
    canEditRoles: false,
    canApproveMaps: false,
    canEditMaps: true,
    canAccessAdminDashboard: false,
  },
  vip: {
    canEditOwnAccount: true,
    canEditOtherAccounts: false,
    canSuspendAccounts: false,
    canEditRoles: false,
    canApproveMaps: false,
    canEditMaps: false,
    canAccessAdminDashboard: false,
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
  ribbit: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: true,
  },
  hizuru_chan: {
    canEditOwnAccount: true,
    canEditOtherAccounts: true,
    canSuspendAccounts: true,
    canEditRoles: true,
    canApproveMaps: true,
    canEditMaps: true,
    canAccessAdminDashboard: true,
  },
  wiki_editor: {
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

// Rate limit for account creation
const Redis = require(`ioredis`);
const redis = new Redis(process.env.REDIS_URL);
const axios = require('axios');


app.use(limiter);

const RATE_LIMIT_WINDOW = 30 * 24 * 60 * 60; // 30 days
const DAILY_LIMIT= 2 // 2 accounts per day

// CAPTCHA Verification Middleware
const verifyCaptcha = async (req, res, next) => {
  const captchaResponse = req.body.captchaResponse;
  if (!captchaResponse) { 
    return res.status(400).json({ error: "CAPTCHA is required" });
  }

  try {
    const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captchaResponse}`);
    if (response.data.success) {
      next(); 
    } else {
      return res.status(400).json({ error: "CAPTCHA verification failed" });
    }
  } catch (error) {
    console.error("CAPTCHA verification error:", error);
    return res.status(500).json({ error: "Server error" });
  }
};
const rateLimitSignup = async (req, res, next) => {
  const ip = req.clientIp;
  const currentTime = Date.now();
  const today = new Date().toISOString().split('T')[0];

  try {
    const dailyCountKey = `${ip}:${today}`;
    const totalCountKey = `${ip}:total`;

    const dailyCount = await redis.get(dailyCountKey);
    const totalCount = await redis.get(totalCountKey);

    if (totalCount && currentTime - totalCount < RATE_LIMIT_WINDOW * 1000) {
      const timeLeft = RATE_LIMIT_WINDOW * 1000 - (currentTime - totalCount);
      const daysLeft = Math.ceil(timeLeft / (24 * 60 * 60 * 1000));
      return res.status(429).json({ error: `Rate limit exceeded, try again in ${daysLeft} days` });
    }

    if (dailyCount && dailyCount >= DAILY_LIMIT) {
      await redis.set(totalCountKey, currentTime);
      await redis.expire(totalCountKey, RATE_LIMIT_WINDOW);
      return res.status(429).json({ error: "Daily account creation limit exceeded" });
    }

    await redis.incr(dailyCountKey);
    await redis.expire(dailyCountKey, 24 * 60 * 60);

    next();
  } catch (error) {
    console.error(' Rate limit error:', error);
    return res.status(500).json({ error: "Server error" });
  }
};

// Validate UUID format
function validateUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// Routes
// Login endpoint - uses username/password
app.post("/v1/account/login", verifyCaptcha, async (req, res) => {
  console.log("Login attempt - Request body:", req.body);

  const { username, password } = req.body;

  if (!username || !password) {
    console.log("Missing username or password");
    return res.status(400).json({
      error: "Username and password required",
    });
  }

  try {
    const userQuery = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

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
      return res.status(403).json({ error: "This account has been suspended" });
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

    // Update last login IP
    await pool.query(
      "UPDATE users SET last_login_ip = $1 WHERE id = $2",
      [req.clientIp, user.id]
    );

    console.log(`User logged in from IP: ${req.clientIp}`);

    return res.status(200).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role_perms: user.role_perms,
        is_staff: user.is_staff,
        signup_ip: user.signup_ip,
        last_login_ip: user.last_login_ip
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ error: "Server error" });
  }
});

// Signup
app.post("/v1/account/signup", verifyCaptcha, rateLimitSignup, async (req, res) => {
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

  if (!isAllowedEmailDOmain(email)) {
    console.error(`Sign-up failed: A account has used a email that is not on our allow list: ${email}`);
    return res.status(400).json({ error: "Sorry this domain is not allowed" });
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
      "INSERT INTO users (nickname, username, email, password, signup_ip) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [nickname, username, email, bcryptHashedPassword, req.clientIp]
    );

    console.log(`New signup from IP: ${req.clientIp}`);
    
    
    app.get("/v1/account/verify-email", async (req, res) => {
      const { token } = req.query;
    
      if (!token) {
        return res.status(400).json({ error: "Invalid verification link" });
      }
    
      const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    
      try {
        const userQuery = await pool.query("SELECT * FROM users WHERE email_token = $1", [hashedToken]);
        if (userQuery.rows.length === 0) {
          return res.status(400).json({ error: "Invalid or expired token" });
        }
    
        // Update the user's verification status
        const email = userQuery.rows[0].email;
        await pool.query("UPDATE users SET is_verified = $1, email_token = NULL WHERE email = $2", [true, email]);
    
        res.status(200).json({ message: "Email verified successfully." });
      } catch (error) {
        console.error("Error verifying email:", error);
        res.status(500).json({ error: "Something went wrong." });
      }
    });
    

    res.status(201).json({ message: "Account created" });
  } catch (error) {
    console.error("Error during signup:", error);
    if (error.code === '23505') {  // Unique violation error code in Postgres
      return res.status(400).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Server error" });
  }
});



// UUID list endpoint
app.get("/v1/account/users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, nickname, role_perms, is_staff, is_suspended FROM users ORDER BY username ASC"
    );
    
    const users = result.rows.map(row => ({
      uuid: row.id,
      display_name: row.nickname,
      username: row.username,
      role: row.role_perms,
      staff: row.is_staff,
      suspended: row.is_suspended
    }));
    
    res.status(200).json({ 
      total: users.length,
      users: users 
    });
  } catch (error) {
    console.error("Error fetching UUIDs:", error);
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
