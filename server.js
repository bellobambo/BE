const express = require("express");
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

app.use(function (req, res, next) {
  res.locals.errors = [];
  next();
});

app.get("/", (req, res) => {
  res.render("homepage");
});

app.get("/login", (req, res) => {
  res.render("login");
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

  if (!req.body.password) errors.push("You  must provide a Password");
  if (!req.body.password && req.body.length < 8)
    errors.push("Password must be at least 8 Characters");
  if (!req.body.password && req.body.length > 70)
    errors.push("Password must be less than 70 chars");

  if (errors.length) {
    return res.render("homepage", { errors });
  }
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
