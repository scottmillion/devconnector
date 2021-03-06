const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = function (req, res, next) {
  // Get token from header
  const token = req.header('x-auth-token')

  // Check if no token
  if (!token) {
    // 401 means not found
    return res.status(401).json({ msg: 'No token, authorization denied' })
  }

  // Verify Token
  try {
    const decoded = jwt.verify(token, config.get('jwtToken'))
    req.user = decoded.user
    next()
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' })
  }
}
