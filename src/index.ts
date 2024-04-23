import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import router from './router/router';

const app = express();

app.use(cors());

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(router);

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`hello on http://localhost:${PORT}`);
});
