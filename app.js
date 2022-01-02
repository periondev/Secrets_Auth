//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");

const md5 = require("md5");

const app = express();

//
console.log(process.env.API_KEY);
const port = 3000;
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies

//connect mongodb
mongoose.connect("mongodb://localhost:27017/userDB");

//define userSchema: Mongoose Schema class object,依照mongoose官網 quick start撰寫
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});
//Secret String Instead of Two Keys

// Add plugins or middleware here. For example, middleware for hashing passwords

//define User Model:
const User = mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  res.render("register");
});
app.listen(port, () => {
  console.log(" connnected at 3000");
});
app.post("/register", (req, res) => {
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password),
  });
  //Save user data
  newUser.save((err) => {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets");
    }
  });
});
//刪除所有的文檔:If Authentication Error happened, delete the old documents and register new users then login. It will work!
// User.deleteMany({}, (err) => {
//   console.log("successful delete");
// });

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = md5(req.body.password);
  User.findOne({ email: username }, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        if (foundUser.password === password) {
          res.render("secrets");
        }
      }
    }
  });
});
