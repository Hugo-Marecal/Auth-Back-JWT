import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import router from './router/router';

const app = express();

app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }),
);

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use('/api', router);

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`hello on http://localhost:${PORT}`);
});
