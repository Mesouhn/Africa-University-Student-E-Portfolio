
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

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

function response(statusCode, message) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ message })
  };
}


exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return response(405, "Method not allowed.");
  }

  let createdAuthUid = null;

  try {
    const headers = event.headers || {};
    const authorization =
      headers.authorization || headers.Authorization;

    if (!authorization || !authorization.startsWith("Bearer ")) {
      return response(401, "Please sign in first.");
    }

    const firebase = getFirebaseAdmin();
    const auth = firebase.auth;
    const db = firebase.db;

    const token = authorization.substring(7);
    const decoded = await auth.verifyIdToken(token, true);

    if (
      decoded.role !== "admin" ||
      !decoded.adminId
    ) {
      return response(403, "Only the Portal Administrator can manage staff.");
    }

    const adminUser = await auth.getUser(decoded.uid);
    const adminRef = db.collection("administrators").doc(decoded.adminId);
    const adminDoc = await adminRef.get();

    if (
      adminUser.disabled ||
      !adminDoc.exists ||
      adminDoc.data().active !== true ||
      adminDoc.data().uid !== decoded.uid
    ) {
      return response(403, "Administrator access is inactive or unauthorized.");
    }const body = JSON.parse(event.body || "{}");
    const action = body.action;
    if (action === "list") {
  const staffSnapshot = await db.collection("staff").get();

  const staff = staffSnapshot.docs.map(function(doc) {
    const data = doc.data();

    return {
      staffId: doc.id,
      name: data.name || "",
      email: data.email || "",
      active: data.active === true,
      createdAt: data.createdAt
        ? data.createdAt.toDate().toISOString()
        : null
    };
  });
return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ staff: staff })
  };
}

    if (action === "create") {
      const staffId =
        typeof body.staffId === "string" ? body.staffId.trim() : "";

      const name =
        typeof body.name === "string" ? body.name.trim() : "";

      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      const password = body.password;

      if (
        !/^[A-Za-z0-9_-]{1,30}$/.test(staffId) ||
        !name ||
        name.length > 100 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 128
      ) {
        return response(
          400,
          "Enter a valid Staff ID, name, email and password of at least 8 characters."
        );
      }

      const staffRef = db.collection("staff").doc(staffId);
      const existingStaff = await staffRef.get();

      if (existingStaff.exists) {
        return response(409, "This Staff ID is already registered.");
      }

      const emailRecord = await db.collection("staff")
        .where("email", "==", email)
        .limit(1)
        .get();

      if (!emailRecord.empty) {
        return response(409, "This email is already assigned to a staff account.");
      }

      const newUser = await auth.createUser({
        email: email,
        password: password,
        displayName: name,
        disabled: false
      });

      createdAuthUid = newUser.uid;

      await staffRef.create({
        uid: newUser.uid,
        staffId: staffId,
        name: name,
        email: email,
        active: true,
        createdAt: FieldValue.serverTimestamp(),
        createdBy: decoded.adminId
      });

      createdAuthUid = null;

      return {
        statusCode: 201,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Staff account created successfully.",
          staffId: staffId
        })
      };
    }

    if (action === "deactivate" || action === "reactivate") {
      const staffId =
        typeof body.staffId === "string" ? body.staffId.trim() : "";

      if (!/^[A-Za-z0-9_-]{1,30}$/.test(staffId)) {
        return response(400, "Enter a valid Staff ID.");
      }

      const staffRef = db.collection("staff").doc(staffId);
      const staffDoc = await staffRef.get();

      if (!staffDoc.exists) {
        return response(404, "Staff account not found.");
      }

      const staffData = staffDoc.data();

      if (!staffData.uid) {
        return response(403, "Staff account has no linked Authentication account.");
      }

      const shouldActivate = action === "reactivate";

      // Update Firebase Authentication first.
      const previousDisabled = (await auth.getUser(staffData.uid)).disabled;

      await auth.updateUser(staffData.uid, {
        disabled: !shouldActivate
      });

      try {
        const statusUpdate = {
          active: shouldActivate
        };

        if (shouldActivate) {
          statusUpdate.reactivatedAt = FieldValue.serverTimestamp();
          statusUpdate.reactivatedBy = decoded.adminId;
        } else {
          statusUpdate.deactivatedAt = FieldValue.serverTimestamp();
          statusUpdate.deactivatedBy = decoded.adminId;
        }

        await staffRef.update(statusUpdate);
      } catch (updateError) {
        try {
          await auth.updateUser(staffData.uid, {
            disabled: previousDisabled
          });
        } catch (rollbackError) {
          console.error("Could not restore staff Authentication status:", rollbackError);
        }

        throw updateError;
      }

      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: shouldActivate
            ? "Staff account reactivated successfully."
            : "Staff account deactivated successfully.",
          staffId: staffId
        })
      };
    }

    return response(400, "Invalid staff management action.");


  } catch (error) {console.error("Staff management error:", error);
    if (createdAuthUid) {
      try {
        await getFirebaseAdmin().auth.deleteUser(createdAuthUid);
      } catch (cleanupError) {
        console.error(
          "Could not clean up new staff account:",
          cleanupError
        );
      }
    }

    return response(
      500,
      "Could not complete the staff management request."
    );
  }
};