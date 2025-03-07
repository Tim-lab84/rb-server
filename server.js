import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
//import serviceAccountKey from "./react-blog-b0b34-firebase-adminsdk-fbsvc-2fe2b78465.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";

// Schema Imports
import User from "./Schema/User.js";

const server = express();
const PORT = process.env.PORT || 3000;

const {
  FIREBASE_TYPE: type,
  FIREBASE_PROJECT_ID: project_id,
  FIREBASE_PRIVATE_KEY_ID: private_key_id,
  FIREBASE_PRIVATE_KEY: private_key,
  FIREBASE_CLIENT_EMAIL: client_email,
  FIREBASE_CLIENT_ID: client_id,
  FIREBASE_AUTH_URI: auth_uri,
  FIREBASE_TOKEN_URI: token_uri,
  FIREBASE_AUTH_PROVIDER_X509_CERT_URL: auth_provider_x509_cert_url,
  FIREBASE_CLIENT_X509_CERT_URL: client_x509_cert_url,
  FIREBASE_UNIVERSE_DOMAIN: universe_domain,
} = process.env;

const serviceAccountKey = {
  type,
  project_id,
  private_key_id,
  private_key,
  client_email,
  client_id,
  auth_uri,
  token_uri,
  auth_provider_x509_cert_url,
  client_x509_cert_url,
  universe_domain,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors());
server.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
});

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

const formatDataToSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

//check if Username already exists -> add random number if it does

const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let usernameExists = await User.exists({
    "personal_info.username": username,
  }).then((result) => result);

  usernameExists ? (username += nanoid().substring(0, 5)) : "";
  return username;
};
// ROUTING
server.post("/signup", async (req, res) => {
  let { fullname, email, password } = req.body;

  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Fullname must be at least 3 letters long" });
  }
  if (!email.length) {
    return res.status(403).json({ error: "Enter Email" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email is invalid" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long and contain a numeric, 1 uppercase and 1 lowercase letter",
    });
  }

  try {
    let hashedPassword = await bcrypt.hash(password, 10);
    let username = await generateUsername(email);

    let user = new User({
      personal_info: { fullname, email, password: hashedPassword, username },
    });

    let savedUser = await user.save();
    return res.status(200).json(formatDataToSend(savedUser));
  } catch (err) {
    if (err.code == 11000) {
      return res.status(500).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: err.message });
  }
});

server.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Find user by email (case-insensitive)
    const user = await User.findOne({
      "personal_info.email": email.toLowerCase(),
    });

    if (!user) {
      return res.status(404).json({ error: "Email not found" });
    }

    // Explicit check for password
    if (!user.personal_info.password) {
      return res.status(500).json({ error: "User account is incomplete" });
    }

    try {
      // Compare passwords
      const isMatch = await bcrypt.compare(
        password,
        user.personal_info.password
      );

      if (!isMatch) {
        return res.status(401).json({ error: "Incorrect Password" });
      }

      // Successful login
      return res.status(200).json(formatDataToSend(user));
    } catch (compareError) {
      console.error("Bcrypt comparison error:", {
        name: compareError.name,
        message: compareError.message,
        stack: compareError.stack,
      });

      return res.status(500).json({
        error: "Password validation failed",
        details: compareError.message,
      });
    }
  } catch (err) {
    console.error("Signin process error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.post("/google-auth", async (req, res) => {
  const { access_token } = req.body;

  try {
    // Verify the ID token
    const decodedUser = await getAuth().verifyIdToken(access_token);
    const { email, name, picture } = decodedUser;

    // Replace profile picture with higher resolution
    const profilePicture = picture.replace("s96-c", "s384-c");

    // Try to find existing user
    let user = await User.findOne({ "personal_info.email": email }).select(
      "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
    );

    // Handle existing user
    if (user) {
      if (!user.google_auth) {
        return res.status(403).json({
          error:
            "This email was signed up without google. Please login with password to access the account",
        });
      }
    } else {
      // Create new user if not exists
      const username = await generateUsername(email);
      user = new User({
        personal_info: {
          fullname: name,
          email,
          profile_img: profilePicture,
          username,
        },
        google_auth: true,
      });

      await user.save();
    }

    // Send response with formatted user data
    return res.status(200).json(formatDataToSend(user));
  } catch (err) {
    console.error("Google Auth Error:", err);
    return res.status(500).json({
      error: "Failed to authenticate with Google. Please try another account.",
    });
  }
});
server.listen(PORT, () => {
  console.log("Listening on Port -> " + PORT);
});
