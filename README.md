# Fullstack authentication flow

- express.js for the web server
- bcryptjs for hashing passwords
- jwt-js-decode for decoding JWT on sever side

Run <br />
`npm install` <br />
`npm start` <br />

Go to http://localhost:5050/

A code sample of:
- Login with username and password
  - Standard authentication classic flow with username and password
  - Credential Management API for auto login and storing credentials safely on client side
- Federated login with Google
- Login with WebAuthn
  - Identifier-First flow for Web Authentication with passkeys 
