var authController = require('../controllers/authcontroller.js');
var passport = require('passport');
 
module.exports = function(app) {
 
    app.get('/signup', authController.signup);

    app.get('/signin', authController.signin);

	app.get('/dashboard',isLoggedIn, authController.dashboard);

    app.get('/logout', authController.logout);

    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect: '/dashboard',
        failureRedirect: '/signup'
    	}
	));

    app.post('/signin', passport.authenticate('local-signin', {
        successRedirect: '/dashboard',
        failureRedirect: '/signin'
        }
 
    ));

    // Facebook routes

    // route for facebook authentication and login
    app.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

    app.get('/auth/facebook/callback',
        passport.authenticate('facebook', {
            successRedirect : '/dashboard',
            failureRedirect : '/signin'
        }));

	function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
        return next();
    res.redirect('/signin');
	}
 
}

