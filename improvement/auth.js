import jwt from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';

const KC_CERTS_URI = process.env.KC_REALM_URI + '/protocol/openid-connect/certs';

const check = (req, res, next) => {
	const bearer = req.header('authorization');
	if (!bearer) {
		res.status(401).json({
			error: 'Token not provided.',
		});
	}
	const token = bearer.replace(/^Bearer /, '');

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

	return jwt.verify(token, getKey, (err, decoded) => {
		if (err) {
			return res.status(403).json({
				error: err.message,
			});
		}

		next();
	});
};

export default { check };
