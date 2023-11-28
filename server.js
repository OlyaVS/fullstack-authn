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
});

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
});

app.post("/auth/auth-options", (req, res) => {
  const foundUser = findUser(req.body.email);
  // this is for the client to ask the server about possible login options
  console.log(foundUser)
  if (foundUser) {
    res.send({
      password: foundUser.password != false,
      google: foundUser.federated && foundUser.federated.google,
      webauthn: foundUser.webauthn
    })
  } else  {
    res.send({password: true})
  }
});

// register a new login way for the user, after we know who the user is
app.post("/auth/webauth-registration-options", (req, res) =>{
  const user = findUser(req.body.email);

  // options for relying party (server)
  const options = {
    rpName: 'Fullstack auth',
    rpID,
    userID: user.email,
    userName: user.name,
    timeout: 60000,
    attestationType: 'none',

    /* Pass an array of already-registered authenticator IDs
   * for not registering the same device multiple times over the same website
     */
    excludeCredentials: user.devices ? user.devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: dev.transports,
    })) : [],

    authenticatorSelection: {
      userVerification: 'required',
      residentKey: 'required',
    },

    // Two most common algorithms: ES256, and RS256
    supportedAlgorithmIDs: [-7, -257],
  };

  // Temporarily remember this value for verification until we verify an authenticator response
  const regOptions = SimpleWebAuthnServer.generateRegistrationOptions(options)

  // save challenge in the user data for verification
  user.currentChallenge = regOptions.challenge;
  db.write();

  res.send(regOptions);
});

app.post("/auth/webauth-registration-verification", async (req, res) => {
  const user = findUser(req.body.user.email);
  const data = req.body.data;

  const expectedChallenge = user.currentChallenge;

  let verification;

  // verify the expected challenge
  try {
    const options = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyRegistrationResponse(options);
  } catch (error) {
    console.log(error);
    return res.status(400).send({ error: error.toString() });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    // if the device exists -> we have already saved that touch ID for the user on this device
    const existingDevice = user.devices ? user.devices.find(
      device => new Buffer(device.credentialID.data).equals(credentialID)
    ) : false;


    // create new device object and saving it to the user devices array
    if (!existingDevice) {
      const newDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: data.response.transports,
      };
      if (user.devices === undefined) {
        user.devices = [];
      }
      user.webauthn = true;
      user.devices.push(newDevice);
      db.write();
    }
  }

  res.send({ ok: true });
});

app.post("/auth/webauth-login-options", (req, res) =>{
  const user = findUser(req.body.email);
  // if (user==null) {
  //     res.sendStatus(404);
  //     return;
  // }
  const options = {
    timeout: 60000,
    allowCredentials: [],
    devices: user && user.devices ? user.devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: dev.transports,
    })) : [],
    userVerification: 'required',
    rpID,
  };
  const loginOpts = SimpleWebAuthnServer.generateAuthenticationOptions(options);
  if (user) user.currentChallenge = loginOpts.challenge;
  res.send(loginOpts);
});

app.post("/auth/webauth-login-verification", async (req, res) => {
  const data = req.body.data;
  const user = findUser(req.body.email);
  if (user==null) {
    res.sendStatus(400).send({ok: false});
    return;
  }

  const expectedChallenge = user.currentChallenge;

  let dbAuthenticator;

  // we save an idenfitier - binary data that signed and identifies the user for this website only
  const bodyCredIDBuffer = base64url.toBuffer(data.rawId);

  for (const dev of user.devices) {
    const currentCredential = Buffer(dev.credentialID.data);
    if (bodyCredIDBuffer.equals(currentCredential)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    return res.status(400).send({ ok: false, message: 'Authenticator is not registered with this site' });
  }

  let verification;
  try {
    const options  = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        ...dbAuthenticator,
        credentialPublicKey: new Buffer(dbAuthenticator.credentialPublicKey.data) // Re-convert to Buffer from JSON
      },
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyAuthenticationResponse(options);
  } catch (error) {
    return res.status(400).send({ ok: false, message: error.toString() });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  res.send({
    ok: true,
    user: {
      name: user.name,
      email: user.email
    }
  });
});

app.get("*", (req, res) => {
    res.sendFile(__dirname + "public/index.html"); 
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
});

