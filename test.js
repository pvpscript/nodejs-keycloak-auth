const CLIENT_ID = process.env.KC_CLIENT_ID;
const CLIENT_SECRET = process.env.KC_CLIENT_SECRET;
const REALM_URI = process.env.KC_REALM_URI;

const OPENID_TOKEN_URI = REALM_URI + '/protocol/openid-connect/token';
const OPENID_AUTH_URI = REALM_URI + '/protocol/openid-connect/auth';
const OPENID_INTROSPECT_URI = REALM_URI + '/protocol/openid-connect/token/introspect';

const express = require('express');
const app = express()
const port = 9876;

const urlEncodeObjectData = (data) => Object.keys(data)
	.map(k => encodeURIComponent(k) + '=' + encodeURIComponent(data[k]))
	.join('&');

const openUrls = ['/', '/start-login', '/callback', '/refresh-test', '/introspect-test'];
const checkUrl = (url) => openUrls.find(u => u == url) === undefined;

async function openidRefresh(refreshToken) {
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

async function openidToken(code) {
	const data = {
		grant_type: 'authorization_code',
		code: code,
		client_id: CLIENT_ID,
		client_secret: CLIENT_SECRET,
		redirect_uri: 'http://localhost:9876/callback'
	};

	return await fetch(OPENID_TOKEN_URI, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: urlEncodeObjectData(data),
	});
}

async function openidIntrospect(token) {
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

const validateToken = async (headers) => {
	const authorization = headers.authorization;

	if (authorization) {
		const token = authorization.replace(/^Bearer /, '');
		const result = await openidIntrospect(token).then(r => r.json());

		if (!result.active)	
			throw new Error('Token is invalid or expired.');
	} else {
		throw new Error('Token was not provided.');
	}
}

const testing = async function (req, res, next) {
	if (checkUrl(req.url)) {
		console.log(req.headers);
		await validateToken(req.headers);
	}

	next();
}
app.use(testing);

app.get('/', (req, res) => {
	res.send("Hello, World!");
});

app.get('/start-login', (req, res) => {
	const data = {
		client_id: CLIENT_ID,
		response_type: 'code',
		redirect_uri: 'http://localhost:9876/callback',
		scope: 'openid',
		state: 'my_state',
	};

	const loginUri = OPENID_AUTH_URI + "?" + urlEncodeObjectData(data);
	res.redirect(loginUri);
});

app.get('/callback', async (req, res) => {
	const code = req.query.code;
	const result = await openidToken(code).then(r => r.json());
	
	res.send(result);
});

app.get('/introspect-middleware', async (req, res) => {
	res.send("Introspection done!");
});

app.get('/introspect-test', async (req, res) => {
	const authorization = req.headers.authorization;

	const token = authorization.replace(/^Bearer /, '');
	const result = await openidIntrospect(token).then(r => r.json());

	res.send(result);
});

app.get('/refresh-test', async (req, res) => {
	const refresh = req.headers.refreshtoken;
	const result = await openidRefresh(refresh).then(r => r.json());

	res.send(result);
});

app.get('*', (req, res) => {
	res.send('Not found');
});

app.listen(port, function() {
	console.log(`App listening on port ${port}`);
});
