//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

const port = 3000;

app.use(express.static("public"));
//view engine setup
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies
//set session
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
//connect mongodb local
mongoose.connect("mongodb://localhost:27017/userDB");

//define userSchema: Mongoose Schema class object,依照mongoose官網 quick start撰寫
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
  googleId: String,
  facebookId: String,
});

//add plugins or middleware here. For example, middleware for hashing passwords
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//define User Model:
const User = mongoose.model("User", userSchema);

//passport use createStrategy (instead of LocalStrategy, according to passport-local-mongoose doc)
passport.use(User.createStrategy());

//passport 序列化與反序列化 (according to Passport doc)
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

//use Google OAuth20 strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(`The Google ID is ${profile.id}`);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//use Facebook strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(`The Facebook ID is ${profile.id}`);
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

//Google auth route
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/secrets");
  }
);

//Facebook auth route
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/logout", (req, res) => {
  req.logOut();
  res.render("home");
});

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});
//Let users submit their secrets.
app.get("/submit", (req, res) => {
  if (req.isAuthenticated) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", (req, res) => {
  User.register({ username: req.body.username }, req.body.password, (err, user) => {
    if (err) {
      console.log("Error at register.", err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        console.log("successfully add new user.");
        res.redirect("/secrets");
      });
    }
  });
});
//passport local auth route fixing
app.post("/login", (req, res) => {
  const user = new User({ username: req.body.username, password: req.body.password });
  req.login(user, (err) => {
    if (err) {
      console.log(err); //not working
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  const userId = req.user.id;
  //find db if userId exist, save secret message.
  User.findById(userId, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.listen(port, () => {
  console.log("Listening on port 3000");
});
