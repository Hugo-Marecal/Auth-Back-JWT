import { Router } from 'express';
import { createUser, loginUser } from '../controller/controller';
import { isAuth } from '../middleware/auth';

const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Hello from the router !' });
});

router.post('/signup', createUser);
router.post('/login', loginUser);

router.get('/account', isAuth, (req, res) => {
  res.json({ message: 'You are connected' });
});

export default router;
