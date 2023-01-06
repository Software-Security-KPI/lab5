const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const request = require('request');
const morgan = require('morgan');
const jose = require('jose');
require('dotenv').config();
const fs = require('fs');
const port = 3000;

const getTokenOptions = {
  method: 'POST',
  url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  form:
  {
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    audience: process.env.AUTH0_AUDIENCE,
    grant_type: 'client_credentials'
  }
};

const getUserTokenOptions = (login, password) => {
  return {
    method: 'POST',
    url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
    headers: {
      'content-type': 'application/x-www-form-urlencoded'
    },
    form:
    {
      grant_type: 'password',
      username: login,
      password: password,
      audience: process.env.AUTH0_AUDIENCE,
      scope: 'openid offline_access',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET
    }
  };
};

const createUserOptions = (token, login, givenName, familyName, nickname, password) => {
  return {
    method: 'POST',
    url: `https://${process.env.AUTH0_DOMAIN}/api/v2/users`,
    headers: {
      'content-type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      email: login,
      given_name: givenName,
      family_name: familyName,
      nickname,
      connection: 'Username-Password-Authentication',
      password
    })
  };
};

const updateUserTokenOptions = (refreshToken) => {
  return {
    method: 'POST',
    url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
    headers: {
      'content-type': 'application/x-www-form-urlencoded'
    },
    form:
    {
      grant_type: 'refresh_token',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      refresh_token: refreshToken
    }
  };
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('tiny'));

app.get('/', (req, res) => {
  const token = req.cookies.id_token;

  if (token) {
    try {
      // decode the token
      const decodedToken = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());

			return res.json({
				username: decodedToken.nickname,
				logout: 'http://localhost:3000/logout'
			});
    } catch (err) {
      res.status(401).send('invalid token');
    }
  }

  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
  return res
    .clearCookie('access_token')
    .clearCookie('id_token')
    .clearCookie('refresh_token')
    .redirect('/');
});

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  // try to authenticate
  request(getUserTokenOptions(login, password), async (error, response, body) => {
    const { access_token, refresh_token, id_token, expires_in } = JSON.parse(body);

    if (access_token) {
      const algorithm = 'RS256';
      const x509 = fs.readFileSync('./dev-pf2nh4fvsnfpuej5.pem', { encoding: 'utf-8' });
      const publicKey = await jose.importX509(x509, algorithm);
  
      try {
        const verifiedJwt = await jose.jwtVerify(access_token, publicKey, {
          issuer: `https://${process.env.AUTH0_DOMAIN}/`,
          audience: process.env.AUTH0_AUDIENCE,
          algorithms: [algorithm],
          maxTokenAge: 60*60*24
        });
        console.log(verifiedJwt);
      } catch (err) {
        res.status(401).send();
      }
      
      return res
        .cookie('access_token', access_token, {
          httpOnly: true,
          expires: new Date(Date.now() + expires_in * 1000)
        })
        .cookie('refresh_token', refresh_token, {
          httpOnly: true
        })
        .cookie('id_token', id_token, {
          httpOnly: true
        })
        .status(200)
        .json({ expires_in });
    }

    res.status(401).send();
  });
});

app.post('/api/signup', (req, res) => {
  const { login, givenName, familyName, nickname, password } = req.body;

  request(getTokenOptions, (error, response, body) => {
    const { access_token } = JSON.parse(body);

    if (access_token) {
      // create a new user
      request(createUserOptions(access_token, login, givenName, familyName, nickname, password), (err, response, body) => {
        const { message, statusCode, error } = JSON.parse(body);

        // in case there is an error
        if (error && message) {
          res.status(statusCode).send(message);
          return;
        }

        return res.send('User was created successfully');
      });
    } else {
      res.status(401).send();
    }
  });
});


app.post('/api/refreshToken', (req, res) => {
  const refreshToken = req.cookies.refresh_token;

  if (refreshToken) {
    request(updateUserTokenOptions(refreshToken), (error, response, body) => {
      const { access_token, expires_in } = JSON.parse(body);

      if (access_token) {
        return res.cookie('access_token', access_token, {
          httpOnly: true,
          expires: new Date(Date.now() + expires_in * 1000)
        }).send();
      }
      res.status(401).send();
    });
  } else {
    res.status(401).send();
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});