const jwt = require('jsonwebtoken');
const { JwksClient } = require('jwks-rsa');

const KC_CERTS_URI = process.env.KC_REALM_URI + '/protocol/openid-connect/certs';
const JWT_EXPIRATION_OFFSET = process.env.JWT_EXPIRATION_OFFSET;

const check = async (token) => new Promise((resolve, reject) => {
	const client = new JwksClient({
		jwksUri: KC_CERTS_URI,
		cache: true,
	});

	const getKey = (header, callback) => {
		client.getSigningKey(header.kid, (err, key) => {
			const signingKey = key.publicKey || key.rsaPublicKey;
			callback(null, signingKey);
		});
	};

	jwt.verify(token, getKey, (err, decoded) => {
		if (err)
			reject(err);

		resolve(decoded);
	});
});

const isNearExpiration = (token) => {
	const remaining = token.exp - Date.now() / 1000;

	return remaining < JWT_EXPIRATION_OFFSET;
};

module.exports = { check, isNearExpiration };
