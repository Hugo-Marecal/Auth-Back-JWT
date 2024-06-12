import { Router } from 'express';
import { createUser, getAccount, loginUser, logoutUser, verifyEmail } from '../controller/controller';
import { isAuth } from '../middleware/auth';
const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Hello from the router !' });
});

router.post('/signup', createUser);
router.post('/login', loginUser);

router.get('/account', isAuth, getAccount);

router.get('/logout', isAuth, logoutUser);

router.get('/verify/:token', verifyEmail);

export default router;
