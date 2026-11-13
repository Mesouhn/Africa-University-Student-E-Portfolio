const assert = require("assert");
const clean = require("./netlify/functions/save.js").cleanAchievements;

// Test 1: Duplicate titles with different details
const a = [
  { title: "Award", detail: "First", date: "2025-05-01", category: "Academic", evidence: "" },
  { title: "Award", detail: "Second", date: "2025-05-01", category: "Academic", evidence: "" }
];

const r = clean(a, a);
assert(r && r.length === 2 && r[0].id !== r[1].id);

// Test 2: Indistinguishable duplicates must be rejected
const b = [
  { title: "Award", detail: "Same", date: "2025-05-01", category: "Academic", evidence: "" },
  { title: "Award", detail: "Same", date: "2025-05-01", category: "Academic", evidence: "" }
];

assert.strictEqual(clean(b, b), null);

// Test 3: Reviewed achievement history must be preserved
const old = [
  {
    id: "old-1",
    title: "Verified Award",
    detail: "Approved",
    date: "2025-04-01",
    category: "Award",
    evidence: "",
    status: "Verified",
    reason: "Checked",
    reviewedBy: "staff-1"
  }
];

const v = clean([{ ...old[0], title: "Changed" }], old);

assert(v && v[0].title === "Verified Award");
assert(v[0].reviewedBy === "staff-1");

// Test 4: Reviewed achievements cannot be deleted
assert.strictEqual(clean([], old), null);

console.log("All migration tests passed.");
