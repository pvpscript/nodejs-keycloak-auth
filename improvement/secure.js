import auth from './auth.js';
import { Router } from 'express';

const router = Router()

router.use(auth.check);

router.get('/', (req, res) => {
	return res.json({
		msg: 'You just accessed a restricted area!!!',
	});
});

router.get('/hello', (req, res) => {
	return res.json({
		msg: 'Safe Hello World!',
	});
});

export default { router };
