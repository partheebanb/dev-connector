const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator/check');
const gravatar = require('gravatar');
const bycrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

const User = require('../models/User');

// create application/json parser
var jsonParser = bodyParser.json();
 
// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post('/', jsonParser,
    [
        check('name', 'Name is required')
            .not()
            .isEmpty(),
        check('email', 'Need email')
            .isEmail(),
        check('password', 'Please enter a password with 6 or more characters')
            .isLength({ min: 6})
    ],
    
    async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json( {errors: errors.array() });
        }

        const {name, email, password} = req.body;

        try {
            // see if user exists
            let user = await User.findOne({email});
            
            if(user) {
                return res.status(400).json({errors: [ {msg: 'User already exists' }]});
            }


            // get gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            });

            // create new user
            user = new User({
                name,
                email,
                avatar,
                password
            });

            // encrypt password
            const salt = await bycrypt.genSalt(10);
            user.password = await bycrypt.hash(password, salt);

            // save user to database
            await user.save();

            // return jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload, 
                config.get('jwtSecret'), 
                {expiresIn: 36000},
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                }
            );

            //res.send(token);

        } catch(err) {
            console.error(err.message);
            res.status(500).send();
        }

        
        //console.log(req.body);
        
});

module.exports = router;