require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const marked = require("marked");
const sanitizeHTML = require("sanitize-html");
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

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT, title STRING NOT NULL,
    body TEXT  NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
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
  res.locals.filterUserHTML = function (content) {
    return sanitizeHTML(marked.parse(content), {
      allowedTags: ["p", "br", "li", "ol", "strong", "bold", "i", "em", "h1"],
      allowedAttributes: {},
    });
  };

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
    const postStatement = db.prepare(
      "SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC"
    );
    const posts = postStatement.all(req.user.userid);
    return res.render("dashboard", { posts });
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

function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
  res.render("create-post");
});

function sharedPostValidation(req) {
  const errors = [];

  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  req.body.title = sanitizeHTML(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.title) errors.push("You Must Provide a title.");
  if (!req.body.body) errors.push("You Must Provide a Body.");

  return errors;
}

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  const errors = sharedPostValidation(req);
  if (errors.length) {
    return res.render("create-post", { errors });
  }

  const ourStatement = db.prepare(
    "INSERT INTO posts (title, body, authorid, createdDate) VALUES (?,?,?,?)"
  );
  const result = ourStatement.run(
    req.body.title,
    req.body.body,
    req.user.userid,
    new Date().toISOString()
  );

  const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
  const realPost = getPostStatement.get(result.lastInsertRowid);

  res.redirect(`/post/${realPost.id}`);
});

app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect("/");
  }

  if (post.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  res.render("edit-post", { post });
});

app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect("/");
  }

  if (post.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  const errors = sharedPostValidation(req);

  if (errors.length) {
    return res.render("edit-post", { errors });
  }

  const updateStatement = db.prepare(
    "UPDATE posts SET title = ?, body = ? WHERE id = ?"
  );
  updateStatement.run(req.body.title, req.body.body, req.params.id);

  res.redirect(`/post/${req.params.id}`);
});

app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
  const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect("/");
  }

  if (post.authorid !== req.user.userid) {
    return res.redirect("/");
  }

  const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?");
  deleteStatement.run(req.params.id);

  res.redirect("/");
});

app.get(`/post/:id`, (req, res) => {
  const statement = db.prepare(
    `SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid WHERE posts.id= ?`
  );
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect("/");
  }

  const isAuthor = post.authorid === req.user.userid;

  res.render("single-post", { post, isAuthor });
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
