
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");
const { randomUUID } = require("crypto");


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

function isValidDate(date) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;

  const [year, month, day] = date.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));

  return (
    parsed.getUTCFullYear() === year &&
    parsed.getUTCMonth() === month - 1 &&
    parsed.getUTCDate() === day
  );
}
const URL_RE = /^https?:\/\/\S{3,300}$/;

function achievementKey(a) {
return (
(a.title || "") + "|" + (a.date || "")
).toLowerCase();
}

function cleanAchievements(input, existing) {
  if (!Array.isArray(input) || input.length > 50) return null;

  const oldAchievements = Array.isArray(existing) ? existing : [];
  const knownById = new Map();

  oldAchievements.forEach(function(a) {
    if (a.id) knownById.set(a.id, a);
  });

  const out = [];
  const submittedIds = new Set();
  const matchedExisting = new Set();

  for (const a of input) {
    if (!a || typeof a !== "object" || Array.isArray(a)) return null;

    const title = typeof a.title === "string" ? a.title.trim() : "";
    const detail = typeof a.detail === "string" ? a.detail.trim() : "";
    const date = typeof a.date === "string" ? a.date.trim() : "";
    const category = typeof a.category === "string"
      ? a.category.trim()
      : "General";
    const evidence = typeof a.evidence === "string"
      ? a.evidence.trim()
      : "";

    if (
      !title ||
      title.length > 120 ||
      detail.length > 500 ||
      category.length > 40
    ) return null;

    if (date && !isValidDate(date)) return null;
    if (evidence && !URL_RE.test(evidence)) return null;

    const key = achievementKey({ title, date });

    let previous = null;

    if (typeof a.id === "string" && knownById.has(a.id)) {
      previous = knownById.get(a.id);
    } else {
      const candidates = oldAchievements.filter(function(old) {
        return (
          !old.id &&
          achievementKey(old) === key &&
          !matchedExisting.has(old)
        );
      });

      if (candidates.length === 1) {
        previous = candidates[0];
      } else if (candidates.length > 1) {
        const exactMatches = candidates.filter(function(old) {
          return (
            (old.detail || "").trim() === detail &&
            (old.category || "General").trim() === category &&
            (old.evidence || "").trim() === evidence
          );
        });

        if (exactMatches.length !== 1) return null;
        previous = exactMatches[0];
      }
    }

    if (previous && matchedExisting.has(previous)) return null;

    const achievementId = previous && previous.id
      ? previous.id
      : (
          typeof a.id === "string" && /^[\w-]{1,80}$/.test(a.id)
            ? a.id
            : randomUUID()
        );

    if (submittedIds.has(achievementId)) return null;
    submittedIds.add(achievementId);

    if (previous) {
      matchedExisting.add(previous);

      if (previous.status && previous.status !== "Pending") {
        out.push({
          ...previous,
          id: achievementId
        });
        continue;
      }

      out.push({
        ...previous,
        id: achievementId,
        title,
        detail,
        date,
        category,
        evidence,
        status: previous.status || "Pending",
        reason: previous.reason || ""
      });
    } else {
      out.push({
        id: achievementId,
        title,
        detail,
        date,
        category,
        evidence,
        status: "Pending",
        reason: ""
      });
    }
  }

  for (const achievement of oldAchievements) {
    if (
      achievement.status &&
      achievement.status !== "Pending" &&
      !matchedExisting.has(achievement)
    ) {
      return null;
    }
  }

  return out;
}
function cleanRecommendations(input, existing) {
  if (!Array.isArray(input) || input.length > 20) return null;

  const known = new Map((existing || []).map(r => [r.id, r]));
  const out = [];

  for (const r of input) {
    if (!r || typeof r !== "object" || Array.isArray(r)) return null;

    const id = typeof r.id === "string" ? r.id.trim() : "";
    const lecturer = typeof r.lecturer === "string" ? r.lecturer.trim() : "";
    const purpose = typeof r.purpose === "string" ? r.purpose.trim() : "";
    const points = typeof r.points === "string" ? r.points.trim() : "";
    const date = typeof r.date === "string" ? r.date.trim() : "";

    if (
      !/^[\w-]{1,40}$/.test(id) ||
      !lecturer ||
      lecturer.length > 80 ||
      !purpose ||
      purpose.length > 120 ||
      points.length > 500
    ) return null;

   if (date && !isValidDate(date)) return null;

    const previous = known.get(id);

    out.push({
      id,
      lecturer,
      purpose,
      points,
      date,
      status: previous && previous.status ? previous.status : "Requested"
    });
  }

  return out;
}

function cleanSkills(input) {
  if (!Array.isArray(input) || input.length > 40) return null;

  const out = [];

  for (const skill of input) {
    if (typeof skill !== "string") return null;

    const value = skill.trim();

    if (!value || value.length > 40) return null;

    out.push(value);
  }

  return out;
}


exports.handler = async (event) => {
  if (event.httpMethod !== "PUT") {
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
        body: JSON.stringify({ message: "Authentication required." })
      };
    }

    const firebase = getFirebaseAdmin();

   const decoded = await firebase.auth.verifyIdToken(
  authorization.substring(7),
  true
);
    const userRecord = await firebase.auth.getUser(decoded.uid);

if (userRecord.disabled) {
  return {
    statusCode: 403,
    body: JSON.stringify({
      message: "This account has been disabled."
    })
  };
}
    if (decoded.role !== "student" || !decoded.studentId) {
      return {
        statusCode: 403,
        body: JSON.stringify({ message: "Student access required." })
      };
    }

    const body = JSON.parse(event.body || "{}");
    const field = body.field;
    const input = body.list;

    const db = firebase.db;
    const studentRef = db.collection("students").doc(decoded.studentId);
    const studentDoc = await studentRef.get();

    if (!studentDoc.exists) {
      return {
        statusCode: 404,
        body: JSON.stringify({ message: "Student profile not found." })
      };
    }

    const studentData = studentDoc.data();

    if (
      studentData.approved !== true ||
      studentData.uid !== decoded.uid
    ) {
      return {
        statusCode: 403,
        body: JSON.stringify({ message: "Student access is not authorized." })
      };
    }

    let cleaned;

    if (field === "achievements") {
      cleaned = cleanAchievements(input, studentData.achievements);
    } else if (field === "recommendations") {
      cleaned = cleanRecommendations(input, studentData.recommendations);
    } else if (field === "skills") {
      cleaned = cleanSkills(input);
    } else {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Invalid update field." })
      };
    }

    if (!cleaned) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Invalid " + field + " list." })
      };
    }

    await studentRef.update({ [field]: cleaned });

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [field]: cleaned })
    };

  } catch (error) {
    console.error("Student update error:", error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        message: "Could not save your changes."
      })
    };
  }
};
module.exports.cleanAchievements = cleanAchievements;