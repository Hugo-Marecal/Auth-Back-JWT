import { Router } from 'express';
import { createUser, loginUser } from '../controller/controller';

const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Hello from the router !' });
});

router.post('/signup', createUser);
router.post('/login', loginUser);

export default router;
