import base64url from "base64url";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import type { NextFunction, Request, Response } from "express";
import express from "express";
import storage from "node-persist";

const __filename = new URL(import.meta.url).pathname;
const __dirname = new URL(".", import.meta.url).pathname;

const AlgorithmIdentifier = {
  Ed25519: -8,
  ES256: -7,
  RS256: -257,
} as const;

const dbUsers = storage.create({ dir: ".data/users" });
await dbUsers.init();

const dbChallenges = storage.create({
  dir: ".data/challenges",
  ttl: 10 * 60 * 1000,
});
await dbChallenges.init();

const app = express();
app.use(cookieParser());

const port = 4455;

// Middleware
app.use(bodyParser.json());

// Utility function to generate random challenges
const generateChallenge = () => base64url(Buffer.from(crypto.randomBytes(32)));

// Log incoming requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`, req.body);
  next();
});

app.get("/", (req: Request, res: Response) => {
  res.sendFile("index.html", { root: __dirname });
});

app.get("/api/auth/me", async (req: Request, res: Response) => {
  // Get username from cookie
  console.log("req.cookies", req.cookies);
  const username = req.cookies.username;

  if (!username) {
    return res.status(401).send({ error: "Not authenticated" });
  }

  const user = await dbUsers.getItem(username);

  if (!user) {
    return res.status(401).send({ error: "User not found" });
  }

  // Send everything but the credential to the client
  const { credential, ...userDetails } = user;
  res.send(userDetails);
});

app.get("/api/auth/logout", (req: Request, res: Response) => {
  res.clearCookie("username");
  res.send({ success: true });
});

// Registration route
app.post("/api/auth/register", async (req: Request, res: Response) => {
  const { displayName, username } = req.body;

  if (!username) {
    return res.status(400).send({ error: "Username is required" });
  }

  // Generate and store a challenge for the user
  const challenge = generateChallenge();
  await dbChallenges.setItem(username, challenge);

  // Send the challenge and registration options to the client
  const registrationOptions = {
    challenge: challenge,
    rp: {
      // id: "example.com",
      name: "My Web App",
    },
    user: {
      id: base64url(Buffer.from(username)),
      name: username,
      displayName: username,
    },
    pubKeyCredParams: [
      {
        alg: AlgorithmIdentifier.ES256,
        type: "public-key",
      },
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "required",
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "direct",
  };

  res.send(registrationOptions);
});

// Registration verification route
app.post(
  "/api/auth/verify-registration",
  async (req: Request, res: Response) => {
    const { credential, username, displayName = username } = req.body;

    if (!username) {
      return res.status(400).send({ error: "Username is required" });
    }
    if (!credential) {
      return res.status(400).send({ error: "Credential are required" });
    }

    // Verify the challenge
    const challenge = await dbChallenges.getItem(username);
    const clientDataJSON = JSON.parse(
      base64url.decode(credential.response.clientDataJSON)
    );
    if (clientDataJSON.challenge !== challenge) {
      return res.status(400).send({ error: "Invalid challenge" });
    }
    await dbChallenges.removeItem(username);

    // Save the credential to the user's account
    dbUsers.setItem(username, { credential, displayName, username });

    res.send({ success: true });
  }
);

// Authentication route
app.post("/api/auth/authenticate", async (req: Request, res: Response) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).send({ error: "No username" });
  }

  const user = await dbUsers.getItem(username);
  if (!user) {
    return res.status(400).send({ error: "User not found" });
  }

  // Generate and store a challenge for the user
  const challenge = generateChallenge();
  await dbChallenges.setItem(username, challenge);

  // Send the challenge and authentication options to the client
  const authenticationOptions = {
    challenge: challenge,
    allowCredentials: [
      {
        type: "public-key",
        id: user.credential.id,
      },
    ],
    timeout: 60000,
    userVerification: "required",
  };

  res.send(authenticationOptions);
});

// Authentication verification route
app.post(
  "/api/auth/verify-authentication",
  async (req: Request, res: Response) => {
    const { username, credential } = req.body;

    if (!username) {
      return res.status(400).send({ error: "No username" });
    }
    if (!credential) {
      return res.status(400).send({ error: "No credential" });
    }

    const user = await dbUsers.getItem(username);
    if (!user) {
      return res.status(400).send({ error: "User not found" });
    }

    // Verify the challenge
    const challenge = await dbChallenges.getItem(username);
    const clientDataJSON = JSON.parse(
      base64url.decode(credential.response.clientDataJSON)
    );
    if (clientDataJSON.challenge !== challenge) {
      return res.status(400).send({ error: "Invalid challenge" });
    }
    await dbChallenges.removeItem(username);

    // Additional verification of the assertion (e.g., signature) would be performed here

    // Set username in cookie
    res.cookie("username", username, { httpOnly: true });
    res.send({ success: true });
  }
);

app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(error.stack);
  res.status(500).send("Something broke!");
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
