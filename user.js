// user.js
var mongoose = require('mongoose');

module.exports  = mongoose.model('User', {

  username: String,
  password: String,
  name: String,
  email: String

});
