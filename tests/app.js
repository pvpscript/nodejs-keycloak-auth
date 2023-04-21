require('dotenv-safe').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const crypto = require('crypto');

const secure = require('./secure');
const keycloak = require('./keycloak');

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
		//domain: 'domain.com',
		sameSite: true,
		path: '/',
		expires: expiryDate,
	},
}));

app.use(cookieParser());

app.use('/secure', secure.router);

app.get('/start-login', (req, res) => {
	const loginUri = keycloak.startLogin();

	res.redirect(loginUri);
});

app.get('/callback', async (req, res, next) => {
	const sessionId = req.session.id;
	console.log(`Session ID: ${sessionId}`);

	const code = req.query.code;
	const result = await keycloak.openidToken(code);

	// Should record session inside a database
	// 'storage' key emulates a database in the cookie storage space.
	req.session['redis_db'] = {
		[sessionId]: result,
	};
	console.log(`REFERER: ${req.headers.referer}`);
	res.redirect('back'); // Should redirect back to the original path
});
//
//app.get('/introspect-middleware', async (req, res) => {
//	res.send("Introspection done!");
//});
//
//app.get('/introspect-test', async (req, res) => {
//	const authorization = req.headers.authorization;
//
//	const token = authorization.replace(/^Bearer /, '');
//	const result = await openidIntrospect(token).then(r => r.json());
//
//	res.send(result);
//});
//
//app.get('/refresh-test', async (req, res) => {
//	const refresh = req.headers.refreshtoken;
//	const result = await openidRefresh(refresh).then(r => r.json());
//
//	res.send(result);
//});
//
//app.get('*', (req, res) => {
//	res.send('Not found');
//});
//
app.get('/', (req, res) => {
	return res.json({
		msg: 'Hello, Worldeh!',
		cookies: req.cookies,
		signedCookies: req.signedCookies,
		sessionId: req.session.id,
		sess: req.session,
	});
});


//app.use((err, req, res, next) => {
//	if (err) {
//		res.status(500).json({
//			msg: 'An error occurred on the root app!',
//			error: err,
//			status: 500,
//		});
//	}
//});

app.listen(port, () => {
	console.log(`App listening on port ${port}`);
});
