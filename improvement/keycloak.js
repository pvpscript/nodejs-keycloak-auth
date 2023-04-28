import { base64URLEncode, sha256 } from './utils.js';

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

export const startLogin = (verifier, state) => {
	const challenge = base64URLEncode(sha256(verifier));
	const data = {
		'client_id': CLIENT_ID,
		'response_type': 'code',
		'redirect_uri': 'http://localhost:9876/callback',
		'code_challenge': challenge,
		'code_challenge_method': 'S256',
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

export const openidToken = async (code, verifier, state) => {
	const payload = {
		'grant_type': 'authorization_code',
		'client_id': CLIENT_ID,
		'client_secret': CLIENT_SECRET,
		'redirect_uri': 'http://localhost:9876/callback',
		'code_verifier': verifier,
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

export default {
	startLogin,
	openidToken,
};
