import keycloak from './keycloak.js';
import { Router } from 'express';
//const { Router } = require('express');
//const keycloak = require('./keycloak');

const router = Router()

router.use(async (req, res, next) => {
	const authorization = req.headers.authorization;

	try {
		//await keycloak.validateToken(authorization);
		console.log("VALIDANDO...");
		await keycloak.validateTokenFromCookie(req.session);
		console.log("VALIDADO COM SUCESSO!!!!!");
		next();
	} catch (err) {
		console.log(err);
		return res
			.redirect('/start-login');
	}
});

router.get('/', (req, res) => {
	console.log(`REFERER: ${req.headers.referer}`);
	console.log("Root!");
	return res.json({
		msg: 'You just accessed a restricted area!!!',
	});
});

router.get('/hello', (req, res) => {
	return res.json({
		msg: 'Safe Hello World!',
	});
});

router.use((err, req, res, next) => {
	if (err) {
		res.status(500).json({
			msg: 'An error occurred in the secure router!',
			status: 500,
		});
	}
});

export default { router };
