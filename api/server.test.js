// Write your tests here
const db = require('../data/dbConfig');
const server = require("./server.js");
const jwt = require('jsonwebtoken');
const request = require('supertest')
const {JWT_SECRET} = require('./secrets/index')

test('sanity', () => {
  expect(true).toBe(true)
})

beforeAll(async () => {
  await db.migrate.rollback();
  await db.migrate.latest();
});

afterAll(async () => {
  await db.destroy();
})

describe('Register', () => {

  test('201 status code received', async ()  => {
    let response = await request(server).post('/api/auth/register').send({username: 'Dexter', password: "1234"});
    expect(response.status).toBe(201)
  })

  test('Correct data object is returned', async () => {
    let response = await request(server).post('/api/auth/register').send({username: 'Des', password: "1234"});
    expect(response.body.username).toBe("Des");
    expect(response.body).toHaveProperty("id");
    expect(response.body).toHaveProperty("username");
    expect(response.body).toHaveProperty("password");

  })
})


describe('Login', () => {

  test('welcome message received', async ()  => {
    let response = await request(server).post('/api/auth/login').send({username: 'Dexter', password: "1234"});
    expect(response.body.message).toBe("welcome, Dexter")
  })

  test('Correct data object is returned', async () => {
    let response = await request(server).post('/api/auth/login').send({password: "1234"});
    expect(response.body.message).toBe("username and password required")

  })
})

describe('Jokes', () => {

  test('Recieve all jokes', async ()  => {
    let response = await request(server).get('/api/jokes').set('Authorization', generateToken({ id: 1, username: 'Dexter' }));
    expect(response.statusCode).toBe(200);
    expect(response.body).toBeInstanceOf(Array);
    expect(response.body).toHaveLength(3);
  })

   

  test('Jokes are not returned', async () => {
    let response = await request(server).get('/api/jokes')
    expect(response.body.message).toBe("token required")
    expect(response.statusCode).toBe(401);
  })
})

function generateToken(user) {
  const payload = {
    subect: user.id,
    username: user.username,
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}