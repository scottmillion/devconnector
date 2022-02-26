const express = require('express')
const router = express.Router()
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const { check, validationResult } = require('express-validator')
const jwt = require('jsonwebtoken')
const config = require('config')

const User = require('../../models/User')

// @route  POST api/users
// @desc   Test route
// @access Public
router.post(
  '/',
  [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    // See if user exists
    const { name, email, password } = req.body

    try {
      let user = await User.findOne({ email })
      // if user is found then throw error because we are creating a new user
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User already exists' }] })
      }

      // Create users gravatar
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm',
      })

      //Create new user
      user = new User({
        name,
        email,
        avatar,
        password,
      })

      // Encrypt password
      const salt = await bcrypt.genSalt(10)
      user.password = await bcrypt.hash(password, salt)

      // Save user
      await user.save()

      // Return jsonwebtoken

      const payload = {
        user: {
          id: user._id,
        },
      }

      jwt.sign(
        payload,
        config.get('jwtToken'),
        { expiresIn: 360000 }, // 3600 in production - optional
        (err, token) => {
          if (err) throw err
          res.json({ token })
        }
      )
    } catch (err) {
      // this will be a server error so we use 500
      console.error(err.message)
      res.status(500).send('Server error')
    }
  }
)

module.exports = router
