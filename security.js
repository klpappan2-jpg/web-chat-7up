// security.js — password hashing + username rules (runs on the server)
import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

/* ---------- passwords: scrypt is built into Node, so there is nothing to install ---------- */
const scryptAsync = promisify(scrypt);
const OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, 32, OPTS);
  return `scrypt$${salt.toString("base64")}$${key.toString("base64")}`;
}

// Used when the name doesn't exist, so response time doesn't reveal which names are registered.
const DUMMY = await hashPassword("timing-equalizer");

export async function verifyPassword(password, stored) {
  const [, saltB64, keyB64] = (stored || DUMMY).split("$");
  const key = await scryptAsync(password, Buffer.from(saltB64, "base64"), 32, OPTS);
  return Boolean(stored) && timingSafeEqual(key, Buffer.from(keyB64, "base64"));
}

/* ---------- usernames ---------- */
const RESERVED = ["admin", "administrator", "root", "system", "moderator", "support", "owner", "null", "undefined"];
const LOOKALIKE = { "0": "o", "1": "l", "!": "l", "|": "l", "3": "e", "4": "a", "@": "a", "5": "s", "$": "s", "7": "t", "8": "b" };

// "Skeleton" = what the name looks like. Same skeleton = same name.
export function skeleton(name) {
  return name.normalize("NFKC").toLowerCase()
    .replace(/[_.\-\s]/g, "")
    .replace(/[01!|3457@$8]/g, c => LOOKALIKE[c])
    .replace(/i/g, "l")
    .replace(/rn/g, "m").replace(/vv/g, "w")
    .replace(/(.)\1+/g, "$1");
}

function editDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}

// Returns an error message, or null if the name is allowed.
export function checkName(name, existingSkeletons) {
  if (!/^[A-Za-z][A-Za-z0-9_.-]{2,15}$/.test(name))
    return "Name must be 3–16 characters, start with a letter, and use only letters, numbers, _ . -";
  const skel = skeleton(name);
  if (RESERVED.some(r => skeleton(r) === skel)) return "That name is reserved";
  for (const s of existingSkeletons) {
    if (s === skel) return "That name is taken or too similar to an existing one";
    if (skel.length >= 6 && editDistance(s, skel) <= 1) return "Too similar to an existing name";
  }
  return null;
}