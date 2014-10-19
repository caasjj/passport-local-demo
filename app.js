// app.js
/******************** Basic Express Stuff ***************/
var express      = require('express');
var logger       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
/*********************************************************/

/******************** Express Session ********************/
var expressSession = require('express-session');
/*********************************************************/

/******************** Configure Mongo(ose) ***************/
var dbConfig = require('./db.js');
var mongoose = require('mongoose');
mongoose.connect(dbConfig.url);
/*********************************************************/

/******************** Load User Schema *******************/
var User = require('./user.js');
var hash = require('bcrypt-nodejs');
var Secret = require('./secret.js');
/*********************************************************/

/******************** Configure Passport *****************/
var passport = require('passport');
var localStrategy = require('passport-local' ).Strategy;

// define default 'local' strategy, used for login
passport.use(new localStrategy(
  // no strategy name (defaults to 'local'), no options, just the verify function
  function(username, password, authCheckDone) {
    User.findOne({ username: username }, function(err, user) {
      if (err) return authCheckDone(err);
      if (!user) return authCheckDone(null, false, 'No such user');
      if (!hash.compareSync(password, user.password)) {
        authCheckDone(null, false, 'Invalid Login');
      }
      authCheckDone(null, user);
    });
  })
);

// define 'signup' strategy, used for login
passport.use('signup', new localStrategy({
    // need req in callback to get post params
    passReqToCallback : true
  },
  // the 'verify' function for this 'signup' strategy
  function(req, password, username, authCheckDone) {
    User.findOne({username: req.param('username' )}, function(err, user) {
      if (err) return authCheckDone(err);
      if (user) {
        return authCheckDone(null,
          false,
          'User ' + req.param('username') + ' already exists.');
      }
      // it's safe, now create the user account
      var user = {
        username: req.param('username' ) || 'johndoe',
        password: hash.hashSync( req.param('password') || 'always42',
                                 hash.genSaltSync(1)),
        name: req.param('name') || 'John Doe',
        email: req.param('email') || 'jd@yahoo.com'
      };
      new User(user ).save( function(err, user) {
        if (err) return authCheckDone(err);
        if (!user) return authCheckDone('Failed on create user :(');
        authCheckDone(null, user);
      });

    });
  })
);

// define the auth verification middleware
function verifyAuth(req,res,next) {
  if ( !req.isAuthenticated() ) {
    return res.json(401, {
      err: 'Please login if you want my secret!',
      sessionId: req.session.id
    });
  }
  next();
}

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
/*********************************************************/

/*************** Create Express Server *******************/
var app = express();
/*********************************************************/

/************ Configure Express Middleware ***************/
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(logger('dev'));
/*********************************************************/

/******************* Configure  Session ******************/
app.use(expressSession({
  secret: 'thisIsTopSecretSoDontTellAnyone',
  cookie: {
    path: '/',
    httpOnly: true,
    secure: false
  }
}));
/*********************************************************/

/******************* Configure Passport ******************/
app.use(passport.initialize());
app.use(passport.session());
/*********************************************************/

/******************* Test Middleware ******************/
app.use(function(req,res,next){
  console.log('Request Object:');
  console.log('Session ID:', req.session.id);
  next();
});
/*********************************************************/

/******************** Configure Routes ******************/
// Hello World server is fuzzy wuzzy
app.get('/', function(req,res) {
  res.send(200, {
    msg: 'Hello World',
    sessionId: req.session.id
  });
});

// route to create an account
app.post('/users', function(req,res,next) {
  passport.authenticate('signup', function(err, user, info) {
    if (err) {
      return res.json(500, {
        err:err,
        sessionId: req.session.id
      });
    }
    if (!user) {
      return res.json( 400,
        {
        err: info,
        sessionId: req.session.id
        });
    }
    req.login(user,  function(err) {
      if (err) {
        return res.json( {
          err: 'Could not login user',
          sessionId: req.session.id
        });
      }
      res.json(201, {
        user: user,
        sessionId: req.session.id
      });
    });
  })(req, res, next);
});

// Login route - note the use 'info' to get back error condition from passport
app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) { return next(err) }
    if (!user) {
      return res.json(401, {
        err: info,
        sessionId: req.session.id
      });
    }
    req.logIn(user, function(err) {
      if (err) {
        return res.json(500, {
          err: 'Could not log user in',
          sessionId: req.session.id
        });
      }
      res.json(200, {
        msg: 'Login success!!',
        sessionId: req.session.id
      });
    });
  })(req, res, next);
});

// logout - destroys the session id, removes req.user
app.get('/logout', function(req, res) {
  req.logout();
  res.json(200, {
    msg: 'Bye!'
  });
});

// Route to read the secret protected by auth
app.get('/secret', verifyAuth,  function(req, res) {

  // gate is open! proceed to read the secret
  Secret.findOne({name:"secret"}, function(err, secret) {
    if (err) {
      return res.json(500, {
        err: 'Could not access secret in dB :('
      });
    }
    res.json(200, {
      secret: secret.secret,
      sessionId: req.session.id
    });
  });

});
/*********************************************************/

/***************** Configure Error Handlers  *************/
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

app.use(function(err, req, res) {
  res.status(err.status || 500);
  res.end(JSON.stringify({
    message: err.message,
    error: {}
  }));
});
/*********************************************************/

/****************** Export Server Module  *****************/
// passport-demo.js will import this module, and we start the server there
module.exports = app;
/*********************************************************/
