const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

// Helper functions to read/write JSON files
const readJsonFile = (filename) => {
  try {
    const filePath = path.join(__dirname, "..", "data", filename);
    const data = fs.readFileSync(filePath, "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error(`Error reading ${filename}:`, error);
    return [];
  }
};

const writeJsonFile = (filename, data) => {
  try {
    const filePath = path.join(__dirname, "..", "data", filename);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 4));
    return true;
  } catch (error) {
    console.error(`Error writing ${filename}:`, error);
    return false;
  }
};

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session && req.session.user) {
    return next();
  } else {
    return res.redirect("/login");
  }
};

const requireAdmin = (req, res, next) => {
  if (req.session && req.session.user && req.session.user.role === "admin") {
    return next();
  } else {
    return res.status(403).json({ error: "Admin access required" });
  }
};

// Routes
router.get("/", requireAuth, (req, res) => {
  const endpoints = readJsonFile("data.json");
  const users = readJsonFile("user.json");

  // Group endpoints by group
  const groupedEndpoints = {};
  endpoints.forEach((endpoint) => {
    const group = endpoint.group || "Other";
    if (!groupedEndpoints[group]) {
      groupedEndpoints[group] = [];
    }
    groupedEndpoints[group].push(endpoint);
  });

  res.render("index", {
    user: req.session.user,
    groupedEndpoints,
    users: req.session.user.role === "admin" ? users : [],
  });
});

router.get("/login", (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect("/");
  }
  res.render("login", { error: null });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const users = readJsonFile("user.json");

  const user = users.find((u) => u.username === username);

  if (user && user.password === password) {
    req.session.user = {
      id: user.id,
      name: user.name,
      username: user.username,
      role: user.role,
    };
    res.redirect("/");
  } else {
    res.render("login", { error: "Invalid username or password" });
  }
});

router.post("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// API Endpoints Management
router.get("/api/endpoints", requireAuth, (req, res) => {
  const endpoints = readJsonFile("data.json");
  res.json(endpoints);
});

router.post("/api/endpoints", requireAdmin, (req, res) => {
  const endpoints = readJsonFile("data.json");
  const newEndpoint = {
    ...req.body,
    id: Date.now().toString(),
  };
  endpoints.push(newEndpoint);

  if (writeJsonFile("data.json", endpoints)) {
    res.json({ success: true, endpoint: newEndpoint });
  } else {
    res.status(500).json({ error: "Failed to save endpoint" });
  }
});

router.put("/api/endpoints/:id", requireAdmin, (req, res) => {
  const endpoints = readJsonFile("data.json");
  const index = endpoints.findIndex((e) => e.id === req.params.id);

  if (index !== -1) {
    endpoints[index] = { ...endpoints[index], ...req.body };
    if (writeJsonFile("data.json", endpoints)) {
      res.json({ success: true, endpoint: endpoints[index] });
    } else {
      res.status(500).json({ error: "Failed to update endpoint" });
    }
  } else {
    res.status(404).json({ error: "Endpoint not found" });
  }
});

router.delete("/api/endpoints/:id", requireAdmin, (req, res) => {
  const endpoints = readJsonFile("data.json");
  const filteredEndpoints = endpoints.filter((e) => e.id !== req.params.id);

  if (writeJsonFile("data.json", filteredEndpoints)) {
    res.json({ success: true });
  } else {
    res.status(500).json({ error: "Failed to delete endpoint" });
  }
});

// User Management (Admin only)
router.get("/api/users", requireAdmin, (req, res) => {
  const users = readJsonFile("user.json");
  res.json(users);
});

router.post("/api/users", requireAdmin, (req, res) => {
  const users = readJsonFile("user.json");
  const newUser = {
    id: Math.max(...users.map((u) => u.id), 0) + 1,
    ...req.body,
  };
  users.push(newUser);

  if (writeJsonFile("user.json", users)) {
    res.json({ success: true, user: newUser });
  } else {
    res.status(500).json({ error: "Failed to save user" });
  }
});

router.put("/api/users/:id", requireAdmin, (req, res) => {
  const users = readJsonFile("user.json");
  const index = users.findIndex((u) => u.id === parseInt(req.params.id));

  if (index !== -1) {
    users[index] = { ...users[index], ...req.body };
    if (writeJsonFile("user.json", users)) {
      res.json({ success: true, user: users[index] });
    } else {
      res.status(500).json({ error: "Failed to update user" });
    }
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

router.delete("/api/users/:id", requireAdmin, (req, res) => {
  const users = readJsonFile("user.json");
  const filteredUsers = users.filter((u) => u.id !== parseInt(req.params.id));

  if (writeJsonFile("user.json", filteredUsers)) {
    res.json({ success: true });
  } else {
    res.status(500).json({ error: "Failed to delete user" });
  }
});

module.exports = router;
