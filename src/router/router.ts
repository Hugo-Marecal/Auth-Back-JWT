import { Router } from 'express';
import { createUser, getAccount, loginUser, logoutUser } from '../controller/controller';
import { isAuth } from '../middleware/auth';

const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Hello from the router !' });
});

router.post('/signup', createUser);
router.post('/login', loginUser);

router.get('/account', isAuth, getAccount);

router.get('/logout', isAuth, logoutUser);

export default router;
