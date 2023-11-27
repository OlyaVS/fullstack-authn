import express from 'express'
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'
import * as url from 'url';
import bcrypt from 'bcryptjs';
import * as jwtJsDecode from 'jwt-js-decode';
import base64url from "base64url";
import SimpleWebAuthnServer from '@simplewebauthn/server';

const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

const app = express()
app.use(express.json())

const adapter = new JSONFile(__dirname + '/auth.json');
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] }

const rpID = "localhost";
const protocol = "http";
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

const findUser = (email) => {
  const results = db.data.users.filter(user => user.email === email);
  return results.length === 0 ? undefined : results[0];
}

// TODO: add data validation
app.post('/auth/register', (req, res) => {
  const salt = bcrypt.genSaltSync(10);
  const hashedPass = bcrypt.hashSync(req.body.password, salt);

  const user = {
    name: req.body.name,
    email: req.body.email,
    password: hashedPass
  }

  const userFound = findUser(user.email);
  if (userFound) {
    res.send({ok: false, message: "User already exists"});
  } else {
    db.data.users.push(user);
    db.write();
    res.send({ok: true});
  }
});

app.post('/auth/login', (req, res) => {
  const userFound = findUser(req.body.email);

  if (userFound) {
    // user found, check password for successful login
    const passwordIsCorrect = bcrypt.compareSync(req.body.password, userFound.password)
    if (passwordIsCorrect) {
      // send public user data to render on the client side
      res.send({ok: true, name: userFound.name, email: userFound.email});
    } else {
      res.send({ok: false, message: "Credentials are incorrect"});
    }

  } else {
    // user not found
    res.send({ok: false, message: "Credentials are incorrect"});
  }
})

app.post('/auth/login-google', (req, res) => {
  // decode JWT string
  const jwt = jwtJsDecode.jwtDecode(req.body.credential);
  console.log(jwt.payload)

  const  user = {
    name: jwt.payload.given_name,
    email: jwt.payload.email,
    password: false,
  }

  const userFound = findUser(user.email);

  if (userFound) {
    user.federated = {
      google: jwt.payload.aud,
    };
    db.write();
  } else {
    db.data.users.push({
      ...user,
      federated: {
        google: jwt.payload.aud,
      }
    })
    db.write();
  }

  res.send({ok: true, name: user.name, email: user.email});

})


app.get("*", (req, res) => {
    res.sendFile(__dirname + "public/index.html"); 
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
});

