
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

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

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return {
      statusCode: 405,
      body: JSON.stringify({ message: "Method not allowed." })
    };
  }

  try {
    const headers = event.headers || {};
    const authorization =
      headers.authorization || headers.Authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return {
        statusCode: 401,
        body: JSON.stringify({
          message: "Authentication required."
        })
      };
    }

    const token = authorization.substring(7);
    const firebase = getFirebaseAdmin();

    const decoded = await firebase.auth.verifyIdToken(token, true);
    const userRecord = await firebase.auth.getUser(decoded.uid);

    if (userRecord.disabled) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "This account has been disabled."
        })
      };
    }

    const role = decoded.role;

    const accountConfig = {
      student: {
        collection: "students",
        id: decoded.studentId
      },
      staff: {
        collection: "staff",
        id: decoded.staffId
      },
      admin: {
        collection: "administrators",
        id: decoded.adminId
      }
    };

    const config = accountConfig[role];

    if (!config || !config.id) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "Your account role is not authorized."
        })
      };
    }

    const accountRef = firebase.db
      .collection(config.collection)
      .doc(config.id);

    const accountDoc = await accountRef.get();

    if (!accountDoc.exists) {
      return {
        statusCode: 404,
        body: JSON.stringify({
          message: "Account profile not found."
        })
      };
    }

    const accountData = accountDoc.data();

    if (accountData.uid !== decoded.uid) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "Account access is not authorized."
        })
      };
    }

    if (role === "student" && accountData.approved !== true) {
      return {
        statusCode: 403,
        body: JSON.stringify({
          message: "Student access is not authorized."
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
        role,
        [role]: {
          ...profile,
          id: config.id
        }
      })
    };

  } catch (error) {
    console.error("Session verification error:", error);

    return {
      statusCode: 401,
      body: JSON.stringify({
        message: "Your session is invalid or has expired."
      })
    };
  }
};
