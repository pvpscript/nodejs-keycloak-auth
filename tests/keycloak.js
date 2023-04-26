import jwt from './jwt.js';

const CLIENT_ID = process.env.KC_CLIENT_ID;
const CLIENT_SECRET = process.env.KC_CLIENT_SECRET;
const REALM_URI = process.env.KC_REALM_URI;

const OPENID_TOKEN_URI = REALM_URI + '/protocol/openid-connect/token';
const OPENID_AUTH_URI = REALM_URI + '/protocol/openid-connect/auth';
const OPENID_INTROSPECT_URI = REALM_URI + '/protocol/openid-connect/token/introspect';

const urlEncodeObjectData = (data) => Object.keys(data)
	.map(k => encodeURIComponent(k) + '=' + encodeURIComponent(data[k]))
	.join('&');

const keycloakRequest = async (payload) => {
	const data = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: urlEncodeObjectData(payload),
	};

	return await fetch(OPENID_TOKEN_URI, data)
		.then(r => r.json())
}

export const startLogin = (state) => {
	const data = {
		'client_id': CLIENT_ID,
		'response_type': 'code',
		'redirect_uri': 'http://localhost:9876/callback',
		scope: 'openid',
		state: state,
	};

	const loginUri = OPENID_AUTH_URI + "?" + urlEncodeObjectData(data);
	return loginUri;
}

const openidRefresh = async (refreshToken) => {
	const payload = {
		'grant_type': 'refresh_token',
		'refresh_token': refreshToken,
		'client_id': CLIENT_ID,
		'client_secret': CLIENT_SECRET,
	};
	
	return await keycloakRequest(payload);
}

export const openidToken = async (code, state) => {
	const payload = {
		'grant_type': 'authorization_code',
		'client_id': CLIENT_ID,
		'client_secret': CLIENT_SECRET,
		'redirect_uri': 'http://localhost:9876/callback',
		code: code,
		state: state,
	};

	return await keycloakRequest(payload);
}

const openidIntrospect = async (token) => {
	const data = {
		'client_id': CLIENT_ID,
		'client_secret': CLIENT_SECRET,
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

export const validateToken = async (auth) => {
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

export const validateTokenFromCookie = async (session) => {
	const storage = session['redis_db']; // emulating a database
	const sessionId = session.id;

	if (storage) {
		const auth = storage[sessionId];
		if (!auth) {
			throw new Error('No authentication data for session id.');
		}

		const token = auth['access_token'];
		if (!token) {
			throw new Error('Token was not provided.');
		}

		const resToken = await jwt.check(token);
		console.log("---------- JWT---------- ");
		console.log(resToken)
		console.log("------------------------------");
		if (jwt.isNearExpiration(resToken)) {
			console.log("TOKEN IS ABOUT TO EXPIRE! REFRESHING!");

			const refreshToken = auth['refresh_token'];
			if (!refreshToken) {
				throw new Error('Refresh token is not present.');
			}
			const newToken = await openidRefresh(refreshToken);
			console.log("---------- NEW TOKEN! ----------");
			console.log(newToken);
			storage[sessionId] = newToken;
		}
	} else {
		throw new Error('Storage not created');
	}
};

export default {
	startLogin,
	openidToken,
	validateToken,
	validateTokenFromCookie
};
