import { Router } from 'express';
import {
  createUser,
  getAccount,
  loginUser,
  logoutUser,
  verifyEmail,
  forgotPassword,
  resetPassword,
} from '../controller/controller';
import { isAuth } from '../middleware/auth';
import { isValidToken } from '../controller/tokenController';
const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Hello from the router !' });
});

router.post('/signup', createUser);
router.post('/login', loginUser);

router.get('/account', isAuth, getAccount);

router.get('/logout', isAuth, logoutUser);

router.get('/verify/:token', verifyEmail);

router.post('/forgot-password', forgotPassword);

router.post('/validate-reset-password-token', isValidToken);

router.post('/reset-password', resetPassword);

export default router;
