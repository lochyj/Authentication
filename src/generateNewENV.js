const crypto = require('crypto');

console.log(`REFRESH_TOKEN_SECRET = "${crypto.createHash('sha256').digest('base64')+crypto.createHash('sha256').digest('base64')}"
ACCESS_TOKEN_SECRET = "${crypto.createHash('sha256').digest('base64')+crypto.createHash('sha256').digest('base64')}"
ACCESS_TOKEN_TIME = "30m"`)