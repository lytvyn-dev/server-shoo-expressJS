const express = require('express');
const {body} = require('express-validator')

const authController = require('../controllers/auth');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login', 
[
	body('email').isEmail().withMessage('Email should be valid'), 
	body('password').trim().isLength({min: 5}).withMessage('Password must be at least 5 characters long')
],
authController.postLogin);

router.post('/signup', 
[
	body('email').isEmail().withMessage('Email should be valid'),
	body('password').trim().isLength({min: 5}).withMessage('Password must be at least 5 characters long'),
	body('confirmPassword').custom((value, {req}) => {
		if(value !== req.body.password){
			throw new Error('Passwords must match!')
		}
 	})
],
authController.postSignup);

router.post('/logout', authController.postLogout);

module.exports = router;