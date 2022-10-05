//jshint esversion:6
require('dotenv').config();
const express = require('express');
const app = express();
const port = 3000;
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

//set session
app.use(
  session({
    secret: 'No one knows',
    resave: true,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

//params of mongoose connection
const connectionParams = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
};

//connect to mongodb atlas (connect your application) + app.listen
mongoose.connect(process.env.CONNECT_DB, connectionParams, (err) => {
  if (err) {
    console.log('Connection failed.');
  } else {
    console.log('Database connected successfully.');
    app.listen(port, () => console.log('Server is running on 3000'));
  }
});

//define userSchema (mongoose quick start)
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
  googleId: String,
  facebookId: String,
});

//add plugins and middleware for hashing passwords
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//define User Model:
const User = mongoose.model('User', userSchema);

//passport use createStrategy (instead of LocalStrategy, according to passport-local-mongoose doc)
passport.use(User.createStrategy());

//passport 序列化與反序列化 (according to Passport doc)
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

//use Google OAuth20 strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
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
      callbackURL: 'http://localhost:3000/auth/facebook/secrets',
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(`The Facebook ID is ${profile.id}`);
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get('/', (req, res) => {
  res.render('home');
});

//Google auth route
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/secrets');
  }
);

//Facebook auth route
app.get('/auth/facebook', passport.authenticate('facebook'));

app.get(
  '/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/secrets');
  }
);

//passport local register route
app.post('/register', (req, res) => {
  User.register({ username: req.body.username }, req.body.password, (err, user) => {
    if (err) {
      console.log('Error at register.', err);
      res.redirect('/register');
    } else {
      passport.authenticate('local')(req, res, () => {
        console.log('successfully add new user.');
        res.redirect('/secrets');
      });
    }
  });
});

//passport local auth route
app.post('/login', (req, res) => {
  const user = new User({ username: req.body.username, password: req.body.password });
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets');
      });
    }
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});
app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/logout', (req, res) => {
  req.logOut();
  res.render('home');
});

//read contents
// secret: { $ne: null }
app.get('/secrets', (req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render('secrets', { usersWithSecrets: foundUsers });
      }
    }
  });
});
//read submit form if user pass auth
app.get('/submit', (req, res) => {
  if (req.isAuthenticated) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

//user submit content
app.post('/submit', (req, res) => {
  const submittedSecret = req.body.secret;
  const userId = req.user.id;

  //find db if userId exist, save content
  User.findById(userId, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      foundUser.secret = submittedSecret;
      foundUser.save(() => {
        res.redirect('/secrets');
      });
    }
  });
});
