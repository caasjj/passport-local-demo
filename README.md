# Demo of Passport local strategy

A simple app demonstrating how to set up and use Passport and the Local Strategy using `passport-local` module
for authentication of users with username+password.

# Use

* `git clone https://github.com/caasjj/passport-local-demo.js`
* `cd passport-local-demo`
* `node passport-local-demo`

You will also need to set up a *Mongo* dB either locally or at [mongolab](https://mongolab.com/).


Then, simply update your database info in `db.js`, and then use a REST client such as `curl` or [Postman](https://twitter.com/postmanclient) to use the server 'api'
at the following routes:

* get  /        : responds with 'Hello World',
* post /signup  : Create user {username:String, password:String, name:String, email:String}',
* post /login   : Authenticate with username/password,
* post /logout  : Logout
* get  /secret  : Return a secret if user is authenticated

<sub>Most definitely intended only to illustrate Passport's api, not a real world implementation.</sub>
