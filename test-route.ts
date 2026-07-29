import request from 'supertest';
import app from './src/app.js'; // Assuming app is exported from src/app.ts
import { generateAuthToken } from './src/utils/jwt.js'; // assuming something like this exists

async function run() {
  const token = 'mockToken'; // test mock uses mockToken or maybe needs a real sign
  const res = await request(app)
      .post('/api/v1/admin/graphql')
      .set('Authorization', `Bearer ${token}`)
      .send({ query: '{ users { id } }' });
  
  console.log(res.status, res.body, res.text);
}

run().catch(console.error);
