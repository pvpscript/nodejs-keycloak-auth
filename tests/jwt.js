const jwt = require('jsonwebtoken');

const secret = process.env.JWT_SECRET;
const expiration = process.env.JWT_EXPIRES_IN;

module.exports.generate = (data) => {
	return jwt.sign(data, secret, {
		expiresIn: parseInt(expiration),
	});
};

module.exports.check = (token) =>
	jwt.verify(token, secret, (err, decoded) => {
		if (err) throw err;

		return decoded;
	});
