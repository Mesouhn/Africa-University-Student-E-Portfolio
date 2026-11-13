
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

function response(statusCode, data) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(data)
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return response(405, { message: "Method not allowed." });
  }

  try {
    const headers = event.headers || {};
    const authorization =
      headers.authorization || headers.Authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return response(401, { message: "Please sign in first." });
    }

    const firebase = getFirebaseAdmin();
    const auth = firebase.auth;
    const db = firebase.db;

    const token = authorization.substring(7).trim();
    const decoded = await auth.verifyIdToken(token, true);

    if (decoded.role !== "admin" || !decoded.adminId) {
      return response(403, {
        message: "Only the Portal Administrator can view achievement oversight."
      });
    }

    const adminUser = await auth.getUser(decoded.uid);
    const adminDoc = await db
      .collection("administrators")
      .doc(decoded.adminId)
      .get();

    if (
      adminUser.disabled ||
      !adminDoc.exists ||
      adminDoc.data().active !== true ||
      adminDoc.data().uid !== decoded.uid
    ) {
      return response(403, {
        message: "Administrator access is inactive or unauthorized."
      });
    }

    const studentsSnapshot = await db
      .collection("students")
      .where("approved", "==", true)
      .get();

    const achievements = [];

    studentsSnapshot.forEach(function(studentDoc) {
      const studentData = studentDoc.data();
      const studentAchievements = Array.isArray(studentData.achievements)
        ? studentData.achievements
        : [];

      studentAchievements.forEach(function(achievement) {
        achievements.push({
          studentId: studentDoc.id,
          studentName: studentData.name || "",
          achievement: achievement
        });
      });
    });

    return response(200, {
      achievements: achievements
    });

  } catch (error) {
    console.error("Achievement oversight error:", error);

    return response(500, {
      message: "Could not load achievement oversight."
    });
  }
};
