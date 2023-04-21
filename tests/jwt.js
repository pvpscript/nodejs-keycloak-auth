const jwt = require('jsonwebtoken');
const { JwksClient } = require('jwks-rsa');

const KC_CERTS_URI = process.env.KC_REALM_URI + '/protocol/openid-connect/certs';

const check = (token) => {
	const client = new JwksClient({
		jwksUri: KC_CERTS_URI,
	});

	const getKey = (header, callback) => {
		client.getSigningKey(header.kid, (err, key) => {
			const signingKey = key.publicKey || key.rsaPublicKey;
			callback(null, signingKey);
		});
	};

	return jwt.verify(token, getKey, (err, decoded) => {
		if (err) throw err;

		return decoded;
	});
};

module.exports = { check };
