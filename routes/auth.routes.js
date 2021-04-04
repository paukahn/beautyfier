const {Router} = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

router.post(
	'/register',
	[
		check('email', 'Некорректный email').isEmail(),
		check('password', 'Пароль должен содержать не менее 6 символов').isLength({
			min: 6
		})
	],
	async (req, res) => {
		try {
			const errors = validationResult(req);

			if (!errors.isEmpty()) {
				return res.status(400).json({
					errors: errors.array(),
					message: 'Некорректные данные при регистрации'
				});
			}

			const {email, password} = req.body;

			const candidate = await User.findOne({email});

			if (candidate) {
				return res.status(400).json({message: 'Ошибка! Email уже занят'});
			}

			const hashedPassword = await bcrypt.hash(password, 12);
			const user = new User({email, password: hashedPassword});

			await user.save();

			res.status(201).json({message: 'Вы успешно зарегистрировались'});
		} catch (e) {
			res
				.status(500)
				.json({message: 'Ошибка сервера. Повторите попытку позднее'});
		}
	}
);

router.post(
	'/login',
	[
		check('email', 'Внимание! Некорректный email!').normalizeEmail().isEmail(),
		check('password', 'Внимание! Некорректный пароль!').exists()
	],
	async (req, res) => {
		try {
			const errors = validationResult(req);

			if (!errors.isEmpty()) {
				return res.status(400).json({
					errors: errors.array(),
					message: 'Некорректные данные при входе в систему'
				});
			}

			const {email, password} = req.body;

			const user = await User.findOne({email});

			if (!user) {
				return res.status(400).json({message: 'Пользователь не найден'});
			}

			const isMatch = await bcrypt.compare(password, user.password);

			if (!isMatch) {
				return res
					.status(400)
					.json({message: 'Внимание! Некорректные данные. Попробуйте еще раз'});
			}

			const token = jwt.sign({userId: user.id}, config.get('jwtSecret'), {
				expiresIn: '1h'
			});

			res.json({token, userId: user.id});
		} catch (e) {
			res
				.status(500)
				.json({message: 'Ошибка сервера. Повторите попытку позднее'});
		}
	}
);

module.exports = router;
