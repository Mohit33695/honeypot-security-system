const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const app = express();
const mysql = require('mysql2');

// 🔥 MySQL Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root', // change if needed
  database: 'honeypot'
});

db.connect(err => {
  if (err) {
    console.error("❌ DB connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL");
  }
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Disable caching
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

let logs = [];
let ipTracker = {};

// Load logs.json
if (fs.existsSync('logs.json')) {
  logs = JSON.parse(fs.readFileSync('logs.json'));
}

// ===============================
// 🔥 RISK SCORE
// ===============================
function getRiskScore(type) {
  switch (type) {
    case "sql_injection": return 5;
    case "xss": return 4;
    case "brute_force": return 3;
    case "suspicious_ip": return 4;
    case "automation_tool": return 5;
    case "bot_activity": return 4;
    default: return 0;
  }
}

// ===============================
// 🤖 AI THREAT LEVEL
// ===============================
function getAIThreatLevel(ip) {
  const userLogs = logs.filter(log => log.ip === ip);
  let score = 0;

  userLogs.forEach(log => score += log.riskScore);

  if (score > 20) return "HIGH";
  if (score > 10) return "MEDIUM";
  return "LOW";
}

// ===============================
// 🤖 AI PATTERN DETECTION
// ===============================
function detectAIPattern(ip) {
  const userLogs = logs.filter(log => log.ip === ip);
  let types = userLogs.map(l => l.attackType);

  if (types.includes("sql_injection")) return "Injection Attack";
  if (types.includes("automation_tool")) return "Automated Bot";
  if (types.includes("brute_force")) return "Credential Attack";
  if (userLogs.length > 10) return "High Frequency Bot";

  return "Normal";
}

// ===============================
// 🔐 LOGIN API
// ===============================
app.post('/login', (req, res) => {

  const username = req.body.username;
  const password = req.body.password;

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = (req.headers['user-agent'] || "").toLowerCase();

  // Track IP
  if (!ipTracker[ip]) {
    ipTracker[ip] = { attempts: 0, lastAttempt: 0 };
  }

  const now = Date.now();
  const timeDiff = now - ipTracker[ip].lastAttempt;

  ipTracker[ip].attempts++;
  ipTracker[ip].lastAttempt = now;

  let attackType = "normal";

  // SQL Injection
  if (password && password.includes("' OR")) {
    attackType = "sql_injection";
  }

  // XSS
  else if (password && password.includes("<script>")) {
    attackType = "xss";
  }

  // Automation tools
  else if (
    userAgent.includes("curl") ||
    userAgent.includes("sqlmap") ||
    userAgent.includes("python") ||
    userAgent.includes("wget") ||
    userAgent.includes("postman") ||
    userAgent.includes("insomnia") ||
    userAgent.includes("powershell") ||
    userAgent === ""
  ) {
    attackType = "automation_tool";
  }

  // Bot speed
  else if (timeDiff < 500) {
    attackType = "bot_activity";
  }

  // Brute force
  const recentAttempts = logs.filter(log =>
    log.username === username &&
    (now - new Date(log.time).getTime()) < 20000
  );

  if (recentAttempts.length >= 3 && attackType === "normal") {
    attackType = "brute_force";
  }

  // Suspicious IP
  if (ipTracker[ip].attempts > 5 && attackType === "normal") {
    attackType = "suspicious_ip";
  }

  // AI Intelligence
  const threatLevel = getAIThreatLevel(ip);
  const pattern = detectAIPattern(ip);

  // ===============================
  // 🔥 LOGGING (JSON + MYSQL)
  // ===============================
  const logData = {
    username,
    password,
    attackType,
    riskScore: getRiskScore(attackType),
    threatLevel,
    pattern,
    ip,
    userAgent,
    time: new Date().toISOString()
  };

  logs.push(logData);
  fs.writeFileSync('logs.json', JSON.stringify(logs, null, 2));

  db.query(
    "INSERT INTO logs (username, password, attackType, riskScore, ip, userAgent) VALUES (?, ?, ?, ?, ?, ?)",
    [
      username,
      password,
      attackType,
      getRiskScore(attackType),
      ip,
      userAgent
    ],
    (err) => {
      if (err) {
        console.error("❌ MySQL Insert Error:", err);
      } else {
        console.log("✅ Log stored in MySQL");
      }
    }
  );

  // ===============================
  // 🚨 AI ALERT SYSTEM
  // ===============================
  if (threatLevel === "HIGH") {
    console.log("🚨 AI ALERT: High-risk attacker detected from IP:", ip);
  }

  // ===============================
  // 🔥 RESPONSES
  // ===============================
  const isTerminal =
    userAgent.includes("curl") ||
    userAgent.includes("powershell") ||
    userAgent.includes("python") ||
    userAgent === "";

  if (attackType === "sql_injection") {
    if (isTerminal) {
      return res.send(`
DATABASE DUMP - USERS TABLE

ID   Name        Email                  Password
---------------------------------------------------------
1    Admin       admin@company.com      admin123
2    User        user@company.com       user123
3    John        john@gmail.com         john@123
4    Alice       alice@yahoo.com        alice@456
5    Rahul       rahul@company.com      rahul@789
6    Sneha       sneha@gmail.com        sneha@111
`);
    }
    return res.sendFile(path.join(__dirname, 'public', 'fake-db.html'));
  }

  if (attackType === "automation_tool" || attackType === "bot_activity") {
    if (isTerminal) {
      return res.send(`
Access Granted...

> whoami
root

> ls
config.php
backup.zip
`);
    }
    return res.sendFile(path.join(__dirname, 'public', 'server-files.html'));
  }

  if (
    attackType === "brute_force" ||
    attackType === "xss" ||
    attackType === "suspicious_ip"
  ) {
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }

  return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ===============================
// APIs
// ===============================

// Hybrid logs (DB + fallback)
app.get('/logs', (req, res) => {
  db.query(
    "SELECT * FROM logs ORDER BY time DESC",
    (err, results) => {
      if (err || !results.length) return res.json(logs);
      res.json(results);
    }
  );
});

app.get('/stats', (req, res) => {
  let stats = {
    total: logs.length,
    sql_injection: 0,
    brute_force: 0,
    xss: 0,
    suspicious_ip: 0,
    automation_tool: 0,
    bot_activity: 0
  };

  logs.forEach(log => {
    if (stats[log.attackType] !== undefined) {
      stats[log.attackType]++;
    }
  });

  res.json(stats);
});

// 🔥 ONLY ADDITION (logs-db route)
app.get('/logs-db', (req, res) => {
  db.query(
    "SELECT * FROM logs ORDER BY time DESC",
    (err, results) => {
      if (err) {
        console.error("❌ DB Fetch Error:", err);
        return res.json([]);
      }
      res.json(results);
    }
  );
});

// Start server
app.listen(3000, '0.0.0.0', () => {
  console.log("🚀 Server running on:");
  console.log("👉 http://localhost:3000/login.html");
});