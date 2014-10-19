// secret.js
var mongoose = require('mongoose');

module.exports  = mongoose.model('Secret', {

  name: String,
  secret: String

});
