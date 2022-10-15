const crypto = require('crypto');

console.log(`
REFRESH_TOKEN_SECRET = "${crypto.randomBytes(127).toString('hex')}"
ACCESS_TOKEN_SECRET = "${crypto.randomBytes(127).toString('hex')}"
ACCESS_TOKEN_TIME = "30m"
`)