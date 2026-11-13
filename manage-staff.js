// ---------------------------------------------------------------------------
// Staff Management API (serverless function, e.g. Netlify Function)
//
// Lets the Portal Administrator manage staff accounts:
//   - list        : return all staff members
//   - create      : create a new staff account (Auth user + Firestore record)
//   - deactivate  : disable a staff account
//   - reactivate  : re-enable a staff account
//
// Only POST requests from a signed-in, active administrator are accepted.
// ---------------------------------------------------------------------------

// Import the Firebase Admin SDK pieces we need:
// - initializeApp / cert / getApps : start and reuse the Firebase app
// - getAuth                        : manage Firebase Authentication users
// - getFirestore / FieldValue      : read/write the database and use server timestamps
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

/**
 * Initializes Firebase Admin (only once) and returns the Auth and Firestore
 * handles. The service account key is read from an environment variable
 * so that no secrets are stored in the source code.
 */
function getFirebaseAdmin() {
  let app;

  // Only initialize if no Firebase app exists yet. Serverless functions can be
  // "warm" and reused, and initializing twice would throw an error.
  if (getApps().length === 0) {
    // The service account JSON is stored base64-encoded in an env variable.
    const encodedKey = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

    // Stop early if the secret has not been configured.
    if (!encodedKey) {
      throw new Error("Firebase service account is not configured.");
    }

    // Decode base64 -> UTF-8 text -> JSON object (the service account credentials).
    const serviceAccount = JSON.parse(
      Buffer.from(encodedKey, "base64").toString("utf8")
    );

    // Start the Firebase app using those credentials.
    app = initializeApp({
      credential: cert(serviceAccount)
    });
  } else {
    // Reuse the app that was already initialized.
    app = getApps()[0];
  }

  // Return the services used by the rest of the code.
  return {
    auth: getAuth(app),
    db: getFirestore(app)
  };
}

/**
 * Small helper that builds a JSON HTTP response with a status code
 * and a single "message" field.
 */
function response(statusCode, message) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ message })
  };
}


// Main entry point: runs every time the function is called.
exports.handler = async (event) => {
  // Only POST requests are allowed (405 = Method Not Allowed).
  if (event.httpMethod !== "POST") {
    return response(405, "Method not allowed.");
  }

  // Tracks a newly created Auth user so we can delete it if a later step fails
  // (prevents "orphan" accounts that exist in Auth but not in Firestore).
  let createdAuthUid = null;

  try {
    // -----------------------------------------------------------------------
    // 1. AUTHENTICATION: read the Bearer token from the request headers
    // -----------------------------------------------------------------------
    const headers = event.headers || {};
    // Header names can arrive in different cases, so check both.
    const authorization =
      headers.authorization || headers.Authorization;

    // Reject the request if there is no "Bearer <token>" header (401 = Unauthorized).
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return response(401, "Please sign in first.");
    }

    const firebase = getFirebaseAdmin();
    const auth = firebase.auth;
    const db = firebase.db;

    // Remove the "Bearer " prefix (7 characters) to get the raw ID token.
    const token = authorization.substring(7);

    // Verify the token with Firebase. The second argument (true) also checks
    // whether the token has been revoked.
    const decoded = await auth.verifyIdToken(token, true);

    // -----------------------------------------------------------------------
    // 2. AUTHORIZATION: make sure the caller is the Portal Administrator
    // -----------------------------------------------------------------------
    // The token must carry the custom claims role = "admin" and an adminId.
    if (
      decoded.role !== "admin" ||
      !decoded.adminId
    ) {
      return response(403, "Only the Portal Administrator can manage staff.");
    }

    // Double-check against live data (not just the token) so that a disabled
    // or removed admin cannot keep using an old token.
    const adminUser = await auth.getUser(decoded.uid);
    const adminRef = db.collection("administrators").doc(decoded.adminId);
    const adminDoc = await adminRef.get();

    if (
      adminUser.disabled ||                    // Auth account is disabled
      !adminDoc.exists ||                      // no matching admin record
      adminDoc.data().active !== true ||       // admin record is not active
      adminDoc.data().uid !== decoded.uid      // record belongs to someone else
    ) {
      return response(403, "Administrator access is inactive or unauthorized.");
    }

    // -----------------------------------------------------------------------
    // 3. READ THE REQUEST: parse the JSON body and pick the action
    // -----------------------------------------------------------------------
    const body = JSON.parse(event.body || "{}");
    const action = body.action;

    // -----------------------------------------------------------------------
    // ACTION: list - return every staff member
    // -----------------------------------------------------------------------
    if (action === "list") {
      const staffSnapshot = await db.collection("staff").get();

      // Convert each Firestore document into a plain object for the client.
      // Only safe fields are returned (e.g. the Auth uid is not exposed).
      const staff = staffSnapshot.docs.map(function(doc) {
        const data = doc.data();

        return {
          staffId: doc.id,
          name: data.name || "",
          email: data.email || "",
          active: data.active === true,
          // Firestore timestamps are converted to ISO date strings.
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

    // -----------------------------------------------------------------------
    // ACTION: create - add a new staff account
    // -----------------------------------------------------------------------
    if (action === "create") {
      // Clean up and normalize each input. If a value is not a string,
      // it becomes an empty string and fails validation below.
      const staffId =
        typeof body.staffId === "string" ? body.staffId.trim() : "";

      const name =
        typeof body.name === "string" ? body.name.trim() : "";

      // Emails are lower-cased so duplicates are detected reliably.
      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      const password = body.password;

      // Validate everything:
      // - Staff ID: 1-30 characters, only letters, numbers, "_" and "-"
      // - Name: required, max 100 characters
      // - Email: basic format check (text@text.text)
      // - Password: a string between 8 and 128 characters
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

      // Make sure this Staff ID is not already in use (409 = Conflict).
      const staffRef = db.collection("staff").doc(staffId);
      const existingStaff = await staffRef.get();

      if (existingStaff.exists) {
        return response(409, "This Staff ID is already registered.");
      }

      // Make sure no other staff record already uses this email.
      const emailRecord = await db.collection("staff")
        .where("email", "==", email)
        .limit(1)
        .get();

      if (!emailRecord.empty) {
        return response(409, "This email is already assigned to a staff account.");
      }

      // Step 1: create the login account in Firebase Authentication.
      const newUser = await auth.createUser({
        email: email,
        password: password,
        displayName: name,
        disabled: false
      });

      // Remember the new uid so the catch block can delete it if step 2 fails.
      createdAuthUid = newUser.uid;

      // Step 2: save the staff profile in Firestore.
      // .create() fails if the document already exists, adding extra protection
      // against two requests using the same Staff ID at the same time.
      await staffRef.create({
        uid: newUser.uid,
        staffId: staffId,
        name: name,
        email: email,
        active: true,
        createdAt: FieldValue.serverTimestamp(), // time set by the server
        createdBy: decoded.adminId               // audit trail: which admin did it
      });

      // Both steps succeeded, so there is nothing to clean up anymore.
      createdAuthUid = null;

      // 201 = Created
      return {
        statusCode: 201,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: "Staff account created successfully.",
          staffId: staffId
        })
      };
    }

    // -----------------------------------------------------------------------
    // ACTION: deactivate / reactivate - turn a staff account off or on
    // -----------------------------------------------------------------------
    if (action === "deactivate" || action === "reactivate") {
      const staffId =
        typeof body.staffId === "string" ? body.staffId.trim() : "";

      // Validate the Staff ID format.
      if (!/^[A-Za-z0-9_-]{1,30}$/.test(staffId)) {
        return response(400, "Enter a valid Staff ID.");
      }

      // Look up the staff record (404 = Not Found).
      const staffRef = db.collection("staff").doc(staffId);
      const staffDoc = await staffRef.get();

      if (!staffDoc.exists) {
        return response(404, "Staff account not found.");
      }

      const staffData = staffDoc.data();

      // The record must be linked to a Firebase Authentication account.
      if (!staffData.uid) {
        return response(403, "Staff account has no linked Authentication account.");
      }

      // true when reactivating, false when deactivating.
      const shouldActivate = action === "reactivate";

      // Update Firebase Authentication first.
      // Save the current "disabled" value so we can roll back if Firestore fails.
      const previousDisabled = (await auth.getUser(staffData.uid)).disabled;

      // Disable (or enable) the login account itself.
      await auth.updateUser(staffData.uid, {
        disabled: !shouldActivate
      });

      try {
        // Build the Firestore update with the new status plus an audit trail.
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
        // Firestore failed, so undo the Authentication change to keep both
        // systems consistent (a simple manual "transaction").
        try {
          await auth.updateUser(staffData.uid, {
            disabled: previousDisabled
          });
        } catch (rollbackError) {
          console.error("Could not restore staff Authentication status:", rollbackError);
        }

        // Re-throw so the outer catch returns a 500 error to the client.
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

    // If the action is none of the above, the request is invalid.
    return response(400, "Invalid staff management action.");


  } catch (error) {
    // -----------------------------------------------------------------------
    // ERROR HANDLING: anything unexpected ends up here
    // -----------------------------------------------------------------------
    // Log the real error on the server only; the client gets a generic message
    // so internal details are never leaked.
    console.error("Staff management error:", error);

    // If an Auth user was created but the Firestore save failed,
    // delete that Auth user so no orphan account is left behind.
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

    // 500 = Internal Server Error
    return response(
      500,
      "Could not complete the staff management request."
    );
  }
};