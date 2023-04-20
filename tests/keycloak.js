const jwt = require('./jwt');

const CLIENT_ID = process.env.KC_CLIENT_ID;
const CLIENT_SECRET = process.env.KC_CLIENT_SECRET;
const REALM_URI = process.env.KC_REALM_URI;

const OPENID_TOKEN_URI = REALM_URI + '/protocol/openid-connect/token';
const OPENID_AUTH_URI = REALM_URI + '/protocol/openid-connect/auth';
const OPENID_INTROSPECT_URI = REALM_URI + '/protocol/openid-connect/token/introspect';

const urlEncodeObjectData = (data) => Object.keys(data)
	.map(k => encodeURIComponent(k) + '=' + encodeURIComponent(data[k]))
	.join('&');

module.exports.startLogin = () => {
	const data = {
		client_id: CLIENT_ID,
		response_type: 'code',
		redirect_uri: 'http://localhost:9876/callback',
		scope: 'openid',
		state: 'my_state',
	};

	const loginUri = OPENID_AUTH_URI + "?" + urlEncodeObjectData(data);
	return loginUri
}

module.exports.openidRefresh = async (refreshToken) => {
	const data = {
		grant_type: 'refresh_token',
		refresh_token: refreshToken,
		client_id: CLIENT_ID,
		client_secret: CLIENT_SECRET,
	};

	return await fetch(OPENID_TOKEN_URI, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: urlEncodeObjectData(data),
	});
}

module.exports.openidToken = async (code) => {
	const payload = {
		grant_type: 'authorization_code',
		code: code,
		client_id: CLIENT_ID,
		client_secret: CLIENT_SECRET,
		redirect_uri: 'http://localhost:9876/callback'
	};

	const data = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: urlEncodeObjectData(payload),
	};

	return await fetch(OPENID_TOKEN_URI, data)
		.then(r => r.json())
		.then(token => jwt.generate(token));
}

const openidIntrospect = async (token) => {
	const data = {
		client_id: CLIENT_ID,
		client_secret: CLIENT_SECRET,
		token: token,
	}

	return await fetch(OPENID_INTROSPECT_URI, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: urlEncodeObjectData(data)
	});
}

module.exports.validateToken = async (auth) => {
	if (auth) {
		const token = auth.replace(/^Bearer /, '');
		const result = await openidIntrospect(token).then(r => r.json());

		if (!result.active)	{
			throw new Error('Token is invalid or expired.');
			//console.log('Token is invalid or expired.');
		}
	} else {
		throw new Error('Token was not provided.');
		//console.log('Token was not provided.');
	}
};

module.exports.validateTokenFromCookie = async (session) => {
	const storage = session['redis_db']; // emulating a database
	const sessionId = session.id;

	if (storage) {
		const auth = storage[sessionId];

		if (auth) {
			const jwtToken = storage[sessionId];
			const jwtData = jwt.check(jwtToken);

			const token = jwtData['access_token'];

			if (!token) {
				throw new Error('Token was not provided.');
			}

			//const validation = await openidIntrospect(token).then(r => r.json());

			//if (!validation.active) {
			//	throw new Error('Token is invalid or expired.');
			//}
		} else {
			throw new Error('No authentication data for session id.');
		}
	} else {
		throw new Error('Storage not created');
	}
};
