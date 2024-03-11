const bcrypt = require('bcryptjs');

const User = require('../models/user');

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
		csrfToken: req.csrfToken()
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false
  });
};

exports.postLogin = (req, res) => {
	const email = req.body.email;
	const password = req.body.password;

  User.findOne({email: email})
    .then(user => {
			if(!user) return res.redirect('/login')
			bcrypt.compare(password, user.password)
			.then(doMatch => {
					if (doMatch) {
							req.session.isLoggedIn = true;
							req.session.user = user;
							return req.session.save(err => {
									if (err) {
											console.log(err);
									}
									res.redirect('/');
							});
					} else {
							return res.redirect('/login');
					}
			})
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
	const email = req.body.email;
	const password  = req.body.password;
	const confirmPassword = req.body.confirmPassword;

	User.findOne({email: email})
	.then((user) => {
		if(user){
			return res.redirect('/signup')
		}else{
			return bcrypt.hash(password, 12)
			.then((encryptedPassword) => {
				return new User({
					email: email,
					password: encryptedPassword
				}).save()
			})
			.then(() => {
				res.redirect('/login')
			})
		}
	})
	.catch(err => console.log(err)); 
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};