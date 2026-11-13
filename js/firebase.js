
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.0/firebase-app.js";

import {
  getAuth,
  signInWithEmailAndPassword,
  signInWithCustomToken,
  signOut,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence,
  onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.14.0/firebase-auth.js";

import {
  getFirestore,
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.14.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyDivcqfaocsU4uJrbb1qqL9oIy3j-eLa94",
  authDomain: "student-portfolio-a82ff.firebaseapp.com",
  projectId: "student-portfolio-a82ff",
  storageBucket: "student-portfolio-a82ff.firebasestorage.app",
  messagingSenderId: "294897032865",
  appId: "1:294897032865:web:4f365bc6aa9307ac441ae0"
};

const app = initializeApp(firebaseConfig);

const auth = getAuth(app);
const db = getFirestore(app);

window.portalFirebase = {
  auth,
  db,
  signInWithEmailAndPassword,
  signInWithCustomToken,
  signOut,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence,
  doc,
  onAuthStateChanged,
  getDoc
}; window.dispatchEvent(new Event("portalFirebaseReady"));
console.log("Firebase connected successfully.");
