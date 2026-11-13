const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, Timestamp } = require("firebase-admin/firestore");

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
  if (event.httpMethod !== "POST") {
    return response(405, { message: "Method not allowed." });
  }

  try {
    const headers = event.headers || {};
    const authorization =
      headers.authorization || headers.Authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return response(401, {
        message: "Please sign in first."
      });
    }

    const firebase = getFirebaseAdmin();
    const auth = firebase.auth;
    const db = firebase.db;

  const token = authorization.substring(7).trim();


const decoded = await auth.verifyIdToken(token, true);

    if (decoded.role !== "staff" || !decoded.staffId) {
      return response(403, {
        message: "Staff access required."
      });
    }

    const staffUser = await auth.getUser(decoded.uid);
    const staffRef = db.collection("staff").doc(decoded.staffId);
    const staffDoc = await staffRef.get();

    if (
      staffUser.disabled ||
      !staffDoc.exists ||
      staffDoc.data().active !== true ||
      staffDoc.data().uid !== decoded.uid
    ) {
      return response(403, {
        message: "Staff account is inactive or unauthorized."
      });
    }

    const staffData = staffDoc.data();
    const body = JSON.parse(event.body || "{}");
    const action = body.action;

    if (action !== "list" && action !== "history" &&
        action !== "review") {
      return response(400, {
        message: "Invalid review action."
      });
    }

    // Retrieve pending achievements or previously reviewed achievements.
    if (action === "list" || action === "history") {
      const studentsSnapshot = await db.collection("students")
  .where("approved", "==", true)
  .get();
        const results = [];
      studentsSnapshot.forEach(function(studentDoc) {
        const studentData = studentDoc.data();
        const achievements = Array.isArray(studentData.achievements)
          ? studentData.achievements
          : [];

        achievements.forEach(function(achievement) {
          const status = achievement.status || "Pending";

          if (
            action === "list" && status === "Pending"
          ) {
            results.push({
              studentId: studentDoc.id,
              studentName: studentData.name || "",
              achievement: achievement
            });
          }

          if (
            action === "history" &&
            (status === "Verified" || status === "Rejected")
          ) {
            results.push({
              studentId: studentDoc.id,
              studentName: studentData.name || "",
              achievement: achievement
            });
          }
        });
      });

      return response(200, {
        achievements: results
      });
    }

    // Approve or reject one pending achievement.
    const studentId =
      typeof body.studentId === "string" ? body.studentId.trim() : "";

    const achievementId =
      typeof body.achievementId === "string"
        ? body.achievementId.trim()
        : "";

    const decision = body.decision;
    const reason =
      typeof body.reason === "string" ? body.reason.trim() : "";

    if (
      !/^[A-Za-z0-9_-]{1,50}$/.test(studentId) ||
      !/^[\w-]{1,80}$/.test(achievementId) ||
      (decision !== "approve" && decision !== "reject") ||
      reason.length > 500 ||
      (decision === "reject" && !reason)
    ) {
      return response(400, {
        message: "Invalid review details. A rejection must include a reason."
      });
    }

    const studentRef = db.collection("students").doc(studentId);

    const result = await db.runTransaction(async function(transaction) {
      const studentDoc = await transaction.get(studentRef);

      if (!studentDoc.exists) {
        return { error: "Student record not found.", status: 404 };
      }

      const studentData = studentDoc.data();
      const achievements = Array.isArray(studentData.achievements)
        ? studentData.achievements
        : [];

      const index = achievements.findIndex(function(item) {
        return item.id === achievementId;
      });

      if (index === -1) {
        return {
          error: "Achievement not found.",
          status: 404
        };
      }

      const previous = achievements[index];

      if ((previous.status || "Pending") !== "Pending") {
        return {
          error: "This achievement has already been reviewed.",
          status: 409
        };
      }

      const reviewedAt = Timestamp.now();
      const status = decision === "approve" ? "Verified" : "Rejected";

      const review = {
        status: status,
        reason: reason,
        reviewedBy: decoded.staffId,
        reviewedByName: staffData.name || "",
        reviewedAt: reviewedAt
      };

      const updatedAchievement = {
        ...previous,
        ...review,
        reviewHistory: [
          ...(Array.isArray(previous.reviewHistory)
            ? previous.reviewHistory
            : []),
          review
        ]
      };

      achievements[index] = updatedAchievement;

      transaction.update(studentRef, {
        achievements: achievements
      });

      return {
        success: true,
        achievement: {
          ...updatedAchievement,
          reviewedAt: reviewedAt.toDate().toISOString()
        }
      };
    });

    if (result.error) {
      return response(result.status, {
        message: result.error
      });
    }

    return response(200, {
      message: decision === "approve"
        ? "Achievement approved successfully."
        : "Achievement rejected successfully.",
      achievement: result.achievement
    });

  } catch (error) {
    console.error("Achievement review error:", error);

    return response(500, {
      message: "Could not complete the achievement review."
    });
  }
};
