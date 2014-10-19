#!/usr/bin/env node
var debug = require('debug')('passport-mongo');
var app = require('./app');

app.set('port', process.env.PORT || 3000);

console.log(app.get('env'));

var server = app.listen(app.get('port'), function() {
  debug('Express server listening on port ' + server.address().port);
});