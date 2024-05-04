import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import prisma from '../dbClient';
import jwt from 'jsonwebtoken';

interface CreateUserRequest extends Request {
  body: {
    email: string;
    username: string;
    password: string;
    confirmPassword: string;
  };
}

export const createUser = async (req: CreateUserRequest, res: Response) => {
  try {
    const { email, username, password, confirmPassword } = req.body;

    if (!email || !username || !password || !confirmPassword) {
      res.status(401);
      res.json({ errMessage: 'Please complete all fields' });
      return;
    }

    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailRegex.test(email)) {
      res.status(401);
      res.json({ errMessage: 'Email not valid' });
      return;
    }

    const alreadyExistingUser = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (alreadyExistingUser) {
      res.status(401);
      res.json({ errMessage: 'This email is already use' });
      return;
    }

    if (password !== confirmPassword) {
      res.status(401);
      res.json({ errMessage: "Passwords don't match" });
      return;
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      res.status(401);
      res.json({
        errMessage:
          'The password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character and have a minimum length of 8 characters.',
      });
      return;
    }

    const numberSaltRounds = parseInt(process.env.NB_OF_SALT_ROUNDS || '7', 10);
    const hashedPassword = await bcrypt.hash(password, numberSaltRounds);

    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });

    if (!newUser) {
      res.status(401);
      res.json({ errMessage: 'Creation failed' });
      return;
    }

    res.json({ successMessage: 'Your account has been created' });
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json('Internal server error');
    return;
  }
};

interface User {
  id: string;
  createdAt: Date;
  email: string;
  username: string;
  password: string;
}

export const loginUser = async (req: CreateUserRequest, res: Response) => {
  try {
    const { email, password } = req.body;

    const user: User | null = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      res.status(401);
      res.json({ errMessage: 'Wrong email/password combination' });
      return;
    }

    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      res.status(401);
      res.json({ errMessage: 'Wrong email/password combination' });
      return;
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_PRIVATE_KEY || 'sshhh', { expiresIn: '24h' });
    res.status(201);
    res.json({ token, successMessage: 'Your are connected' });
  } catch (error) {
    console.error(error);
    res.status(500);
    res.json('Internal server error');
    return;
  }
};
