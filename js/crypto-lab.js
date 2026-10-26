/**
 * Cryptography Educational Lab
 * Demonstrates Hashing, Salting, and Peppering using Web Crypto API
 */

const CryptoLab = (function () {
  /**
   * Helper to convert an ArrayBuffer to a hex string
   */
  function bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Compute standard SHA-256 hash using Web Crypto API
   */
  async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return bufferToHex(hashBuffer);
  }

  /**
   * Generate a random cryptographic hex salt
   */
  function generateRandomSalt(length = 16) {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return bufferToHex(array);
  }

  /**
   * Simulate a multi-step transformation pipeline
   */
  async function computeCryptoPipeline(password, salt, pepper) {
    // 1. Raw Hash
    const rawInput = password;
    const rawHash = await sha256(rawInput);

    // 2. Salted Hash
    const saltedInput = `${password}${salt}`;
    const saltedHash = await sha256(saltedInput);

    // 3. Peppered Hash
    const pepperedInput = `${password}${salt}${pepper}`;
    const pepperedHash = await sha256(pepperedInput);

    return {
      raw: { input: rawInput, hash: rawHash },
      salted: { input: saltedInput, salt: salt, hash: saltedHash },
      peppered: { input: pepperedInput, salt: salt, pepper: pepper, hash: pepperedHash }
    };
  }

  /**
   * Compare two simulated users who have the exact same password
   * to demonstrate how salting eliminates rainbow tables
   */
  async function compareTwinUsers(sharedPassword, pepper) {
    const userA = {
      name: 'Alice',
      password: sharedPassword,
      salt: generateRandomSalt(8)
    };

    const userB = {
      name: 'Bob',
      password: sharedPassword,
      salt: generateRandomSalt(8)
    };

    const rawA = await sha256(userA.password);
    const rawB = await sha256(userB.password);

    const saltedA = await sha256(`${userA.password}${userA.salt}`);
    const saltedB = await sha256(`${userB.password}${userB.salt}`);

    const pepperedA = await sha256(`${userA.password}${userA.salt}${pepper}`);
    const pepperedB = await sha256(`${userB.password}${userB.salt}${pepper}`);

    return {
      userA: { ...userA, rawHash: rawA, saltedHash: saltedA, pepperedHash: pepperedA },
      userB: { ...userB, rawHash: rawB, saltedHash: saltedB, pepperedHash: pepperedB }
    };
  }

  return {
    sha256,
    generateRandomSalt,
    computeCryptoPipeline,
    compareTwinUsers
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = CryptoLab;
}
