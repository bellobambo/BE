require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const db = require("better-sqlite3")("ourApp.db");
db.pragma("journal_mode = WAL");

const createTable = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
  ).run();
});

createTable();

const app = express();

app.use(express.urlencoded({ extended: true }));

app.use(express.json());

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(cookieParser());

app.use(function (req, res, next) {
  res.locals.errors = [];

  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (error) {
    req.user = false;
    console.log(error);
  }

  res.locals.user = req.user;
  console.log(req.user);

  next();
});

app.get("/", (req, res) => {
  if (req.user) {
    return res.render("dashboard");
  }
  res.render("homepage");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  if (req.body.username.trim() == "") errors = ["Invalid username/ password"];
  if (req.body.password.trim() == "") errors = ["Invalid username/ password"];

  if (errors.length) {
    return res.render("login", { errors });
  }

  const userInQuestState = db.prepare("SELECT * FROM users WHERE USERNAME = ?");
  const userInQuest = userInQuestState.get(req.body.username);

  if (!userInQuest) {
    errors = ["invalid username/ password"];
    return res.render("login", { errors });
  }

  const matchOrNot = bcrypt.compareSync(
    req.body.password,
    userInQuest.password
  );

  if (!matchOrNot) {
    errors = ["Invalid username/ password"];
    return res.render("login", { errors });
  }

  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 60 * 24,
      skyColor: "blue",
      userid: userInQuest.id,
      username: userInQuest.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp");
  res.redirect("/");
});

app.get("/create-post", (req, res) => {
  res.render("create-post");
});

app.post("/register", (req, res) => {
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push("You  must provide a username");
  if (!req.body.username && req.body.length < 3)
    errors.push("Username must be  more than 3");
  if (!req.body.username && req.body.length > 10)
    errors.push("Username must be less than 10 chars");

  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers");

  const usernameStatement = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  );
  const usernameCheck = usernameStatement.get(req.body.username);

  if (usernameCheck) errors.push("That username is already taken");

  if (!req.body.password) errors.push("You  must provide a Password");
  if (!req.body.password && req.body.length < 8)
    errors.push("Password must be at least 8 Characters");
  if (!req.body.password && req.body.length > 70)
    errors.push("Password must be less than 70 chars");

  if (errors.length) {
    return res.render("homepage", { errors });
  }

  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  const ourStatement = db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  );

  const result = ourStatement.run(req.body.username, req.body.password);

  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const ourUser = lookupStatement.get(result.lastInsertRowid);

  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 60 * 24,
      skyColor: "blue",
      userid: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.redirect("/");
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
