const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator')

const User = require('../models/user');

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
		csrfToken: req.csrfToken(),
		oldInputs: {
			email: '',
			password: ''
		},
		validationErrors: [],
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
		validationErrors: [],
		oldInputs: {
			email: '',
			password: '',
			confirmPassword: ''
		},
  });
};

exports.postLogin = (req, res) => {
	const email = req.body.email;
	const password = req.body.password;

	const validationErrors = validationResult(req)

	if(validationErrors.isEmpty()){
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
	}

	return res.status(403).render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
		csrfToken: req.csrfToken(),
		oldInputs: {
			email,
			password,
		},
		validationErrors: validationErrors.array(),
  });
};

exports.postSignup = (req, res, next) => {
	const email = req.body.email;
	const password  = req.body.password;
	const confirmPassword = req.body.confirmPassword;

	const validationErrors = validationResult(req)

	if(validationErrors.isEmpty()){
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
	}

	return res.status(403).render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
		validationErrors: validationErrors.array(),
		oldInputs: {
			email,
			password,
			confirmPassword
		}
  });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};
