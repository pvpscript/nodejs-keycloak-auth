import 'dotenv-safe/config.js';

import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import crypto from 'crypto';

import { nanoid } from 'nanoid';

import secure from './secure.js';
import keycloak from './keycloak.js';

const app = express()
const port = 9876;

app.set('json spaces', 4);
app.set('trust proxy', 1);

const expiryDate = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
app.use(session({
	secret: process.env.SESSION_SECRET,
	genid: _ => crypto.randomUUID(),
	name: 'sessionId',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: false, // sends cookie only over https
		httpOnly: true,
		domain: 'localhost',
		sameSite: true,
		path: '/',
		expires: expiryDate,
	},
}));

app.use(cookieParser(process.env.COOKIE_SECRET));

app.use('/secure', secure.router);

app.get('/start-login', (req, res) => {
	const state = nanoid();
	const loginUri = keycloak.startLogin(state);

	const expiry = 60 * 5 * 1000;
	res.cookie('stateParam', state, {
		maxAge: expiry,
		signed: true,
	});

	res.redirect(loginUri);
});

app.get('/callback', async (req, res) => {
	console.log("---------- CALLBACK ROUTE ----------");
	const sessionId = req.session.id;
	console.log(`Session ID: ${sessionId}`);

	const { code, state } = req.query;
	const { stateParam } = req.signedCookies;

	console.log(`Code: ${code}`);
	console.log(`State: ${state}`);
	console.log(`Saved state: ${stateParam}`);

	if (state !== stateParam) {
		res.status(500).json({
			err: 'Invalid state!'
		});
	}

	const result = await keycloak.openidToken(code, state);

	// Should record session inside a database
	// 'storage' key emulates a database in the cookie storage space.
	req.session['redis_db'] = {
		[sessionId]: result,
	};
	console.log(`REFERER: ${req.headers.referer}`);
	res.redirect('back'); // Should redirect back to the original path
});

app.get('/', (req, res) => {
	return res.json({
		msg: 'Hello, Worldeh!',
		cookies: req.cookies,
		signedCookies: req.signedCookies,
		sessionId: req.session.id,
		sess: req.session,
	});
});


app.listen(port, () => {
	console.log(`App listening on port ${port}`);
});
