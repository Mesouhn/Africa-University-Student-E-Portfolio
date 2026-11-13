
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");
const crypto = require("crypto");

const MAX_LOGIN_ATTEMPTS = 5;
const MAX_IP_LOGIN_ATTEMPTS = 100;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const BLOCK_DURATION_MS = 15 * 60 * 1000;

function getFirebaseAdmin() {
  let app;

  if (getApps().length === 0) {
    const encodedKey = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

    if (!encodedKey) {
      throw new Error("Firebase service account is not configured.");
    }

    const serviceAccount = JSON.parse(
      Buffer.from(encodedKey, "base64").toString("utf8")
    );

    app = initializeApp({
      credential: cert(serviceAccount)
    });
  } else {
    app = getApps()[0];
  }

  return {
    auth: getAuth(app),
    db: getFirestore(app)
  };
}

function getLoginAttemptKey(accountId, event) {
  const headers = event.headers || {};

  const ip =
    headers["x-nf-client-connection-ip"] ||
    headers["X-Nf-Client-Connection-Ip"] ||
    "unknown";

  const accountKey = crypto
    .createHash("sha256")
    .update(accountId.toLowerCase() + "|" + ip)
    .digest("hex");

  const ipKey = crypto
    .createHash("sha256")
    .update("IP|" + ip)
    .digest("hex");

  return { accountKey, ipKey };
}

async function checkAndRecordLoginAttempt(db, accountKey, ipKey) {
  const accountRef = db.collection("loginAttempts").doc(accountKey);
  const ipRef = db.collection("loginAttempts").doc(ipKey);

  return db.runTransaction(async (transaction) => {
    const accountDoc = await transaction.get(accountRef);
    const ipDoc = await transaction.get(ipRef);

    const now = Date.now();

    function checkLimit(doc, maxAttempts) {
      let attempts = 0;
      let windowStartedAt = now;

      if (doc.exists) {
        const data = doc.data();

        if (data.blockedUntil > now) {
          return { blocked: true };
        }

        if (
          data.windowStartedAt &&
          now - data.windowStartedAt < LOGIN_WINDOW_MS
        ) {
          attempts = data.attempts || 0;
          windowStartedAt = data.windowStartedAt;
        }
      }

      if (attempts >= maxAttempts) {
        return {
          blocked: true,
          attempts,
          windowStartedAt,
          blockedUntil: now + BLOCK_DURATION_MS
        };
      }

      return {
        blocked: false,
        attempts: attempts + 1,
        windowStartedAt,
        blockedUntil: 0
      };
    }

    const accountLimit = checkLimit(accountDoc, MAX_LOGIN_ATTEMPTS);
    const ipLimit = checkLimit(ipDoc, MAX_IP_LOGIN_ATTEMPTS);

    if (accountLimit.blocked || ipLimit.blocked) {
      if (accountLimit.blockedUntil) {
        transaction.set(accountRef, accountLimit);
      }

      if (ipLimit.blockedUntil) {
        transaction.set(ipRef, ipLimit);
      }

      return true;
    }

    transaction.set(accountRef, accountLimit);
    transaction.set(ipRef, ipLimit);

    return false;
  });
}

async function resetLoginAttempts(db, key) {
  await db.collection("loginAttempts").doc(key).delete();
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ message: "Method not allowed." })
    };
  }

  try {
    const body = JSON.parse(event.body || "{}");

    // Keep compatibility with the existing student login request.
    const accountId = body.accountId || body.studentId;
    const password = body.password;
    const role = body.role || "student";

    if (
      typeof accountId !== "string" ||
      typeof password !== "string" ||
      !accountId.trim() ||
      accountId.trim().length > 30 ||
      !password ||
      password.length > 128 ||
      !["student", "staff", "admin"].includes(role)
    ) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          message: "Enter a valid ID, password and account type."
        })
      };
    }

    const cleanId = accountId.trim();
    const firebase = getFirebaseAdmin();
    const db = firebase.db;

    const attemptKeys = getLoginAttemptKey(cleanId, event);

    if (
      await checkAndRecordLoginAttempt(
        db,
        attemptKeys.accountKey,
        attemptKeys.ipKey
      )
    ) {
      return {
        statusCode: 429,
        body: JSON.stringify({
          message: "Too many login attempts. Please try again in 15 minutes."
        })
      };
    }

    const collectionName = {
      student: "students",
      staff: "staff",
      admin: "administrators"
    }[role];

    const accountRef = db.collection(collectionName).doc(cleanId);
    const accountDoc = await accountRef.get();
        const adminSnapshot = await db.collection("administrators").limit(10).get();
    if (!accountDoc.exists) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          message: "Incorrect ID or password."
        })
      };
    }

    const accountData = accountDoc.data();

    if (
      !accountData.uid ||
      !accountData.email
    ) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "This account is not properly registered."
        })
      };
    }

    if (role === "student" && accountData.approved !== true) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "This student account is not approved."
        })
      };
    }

    if (
      (role === "staff" || role === "admin") &&
      accountData.active !== true
    ) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "This account is inactive or not authorized."
        })
      };
    }

    const apiKey = process.env.FIREBASE_WEB_API_KEY;

    if (!apiKey) {
      throw new Error("Firebase Web API key is not configured.");
    }

    const response = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + apiKey,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: accountData.email,
          password,
          returnSecureToken: true
        })
      }
    );

    if (!response.ok) {
  const authError = await response.json();
  console.error(
    "Firebase login error:",
    authError.error && authError.error.message
  );

  return {
    statusCode: 401,
    body: JSON.stringify({
      message: "Incorrect ID or password."
    })
  };
}

    const authData = await response.json();

    if (authData.localId !== accountData.uid) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          message: "Incorrect ID or password."
        })
      };
    }

    const userRecord = await firebase.auth.getUser(authData.localId);

    if (userRecord.disabled) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "This account has been disabled."
        })
      };
    }

    const claims = { role };

    if (role === "student") {
      claims.studentId = cleanId;
    } else if (role === "staff") {
      claims.staffId = cleanId;
    } else {
      claims.adminId = cleanId;
    }

    const customToken = await firebase.auth.createCustomToken(
      authData.localId,
      claims
    );

    await resetLoginAttempts(db, attemptKeys.accountKey);

    const {
      email,
      uid,
      approved,
      active,
      registeredAt,
      ...profile
    } = accountData;

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        customToken,
        role,
        [role]: {
          ...profile,
          id: cleanId
        }
      })
    };
  } catch (error) {
    console.error("Login error:", error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        message: "Login could not be completed. Please try again."
      })
    };
  }
};
