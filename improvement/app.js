import 'dotenv-safe/config.js';

import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import crypto from 'crypto';

import { nanoid } from 'nanoid';

import secure from './secure.js';
import keycloak from './keycloak.js';

import { base64URLEncode } from './utils.js';

const app = express()
const port = 9876;

app.set('json spaces', 4);

app.use(cookieParser(process.env.COOKIE_SECRET));

app.use('/secure', secure.router);

app.get('/start-login', (req, res) => {
	const state = nanoid();
	const verifier = base64URLEncode(crypto.randomBytes(32));
	const loginUri = keycloak.startLogin(verifier, state);

	const expiry = 60 * 5 * 1000;
	res.cookie('stateParam', state, {
		maxAge: expiry,
		signed: true,
	});
	res.cookie('verifier', verifier, {
		maxAge: expiry,
		signed: true,
	});

	res.redirect(loginUri);
});

app.get('/callback', async (req, res) => {
	const { code, state } = req.query;
	const { stateParam, verifier } = req.signedCookies;

	if (state !== stateParam) {
		res.status(500).json({
			err: 'Invalid state!'
		});
	}

	const result = await keycloak.openidToken(code, verifier, state);

	res.status(201).json(result);
});

app.get('/', (req, res) => {
	return res.json({
		cookies: req.cookies,
		signedCookies: req.signedCookies,
	});
});


app.listen(port, () => {
	console.log(`App listening on port ${port}`);
});
