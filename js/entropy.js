/**
 * Entropy & Crack-Time Calculation Engine
 * Computes Shannon entropy, effective entropy considering heuristic weaknesses,
 * and realistic crack times across various threat vectors.
 */

const EntropyCalc = (function () {
  /**
   * Determine character pool size
   */
  function getPoolSize(str) {
    let pool = 0;
    const hasLower = /[a-z]/.test(str);
    const hasUpper = /[A-Z]/.test(str);
    const hasDigits = /[0-9]/.test(str);
    const hasSpecial = /[^a-zA-Z0-9]/.test(str);

    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigits) pool += 10;
    if (hasSpecial) pool += 33;

    return {
      pool: Math.max(pool, 1),
      hasLower,
      hasUpper,
      hasDigits,
      hasSpecial
    };
  }

  /**
   * Calculate Raw & Effective Entropy in bits
   */
  function calculateEntropy(str, patternResults) {
    if (!str || str.length === 0) {
      return {
        rawEntropy: 0,
        effectiveEntropy: 0,
        poolSize: 0,
        charFlags: { hasLower: false, hasUpper: false, hasDigits: false, hasSpecial: false }
      };
    }

    const { pool, hasLower, hasUpper, hasDigits, hasSpecial } = getPoolSize(str);
    const rawEntropy = str.length * (Math.log2(pool));

    let effectiveEntropy = rawEntropy;

    // If it's a recognized passphrase (Diceware style)
    if (patternResults && patternResults.passphrase && patternResults.passphrase.isPassphrase) {
      // Diceware wordlist has 7776 words = ~12.92 bits per word
      const wordCount = patternResults.passphrase.wordCount;
      const passphraseEntropy = wordCount * 12.92;
      effectiveEntropy = Math.max(passphraseEntropy, rawEntropy * 0.9);
    } else {
      // Deduct penalty from patterns (keyboard walks, dictionary words, etc.)
      const penalty = patternResults ? patternResults.scorePenalty : 0;
      effectiveEntropy = Math.max(0, rawEntropy - penalty);

      // Short passwords under 8 characters receive heavy scaling down
      if (str.length < 8) {
        effectiveEntropy = effectiveEntropy * (str.length / 8);
      }
    }

    return {
      rawEntropy: Math.round(rawEntropy * 10) / 10,
      effectiveEntropy: Math.round(effectiveEntropy * 10) / 10,
      poolSize: pool,
      charFlags: { hasLower, hasUpper, hasDigits, hasSpecial }
    };
  }

  /**
   * Threat models and guesses per second
   */
  const ATTACK_MODELS = {
    // Web login with rate limiting & lockouts (~100 guesses/hour)
    onlineThrottled: {
      name: 'Online Throttled',
      desc: 'Web portal with rate limits & CAPTCHA (100 tries / hour)',
      rate: 100 / 3600 // 0.027 guesses/sec
    },
    // Web login without rate limiting
    onlineFast: {
      name: 'Online Unthrottled',
      desc: 'Poorly protected web API or botnet (1,000 tries / sec)',
      rate: 1000
    },
    // Leaked database with modern slow hash (bcrypt, Argon2, PBKDF2)
    offlineSlow: {
      name: 'Offline Slow Hash (Argon2 / bcrypt)',
      desc: 'GPU cluster attacking salted slow hash (100,000 tries / sec)',
      rate: 100000
    },
    // Leaked database with fast raw hash (MD5, NTLM, SHA-1, raw SHA-256)
    offlineFast: {
      name: 'Offline Fast Hash (MD5 / NTLM / SHA-256)',
      desc: 'High-end cracking rig with 8x RTX 4090 GPUs (100 Billion tries / sec)',
      rate: 100000000000
    }
  };

  /**
   * Convert seconds into human friendly time description
   */
  function formatCrackTime(seconds) {
    if (seconds <= 0.001) return 'Instantly (< 1 ms)';
    if (seconds < 1) return `${Math.round(seconds * 1000)} milliseconds`;
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 86400 * 30) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 86400 * 365) return `${Math.round(seconds / (86400 * 30))} months`;
    if (seconds < 86400 * 365 * 100) return `${Math.round(seconds / (86400 * 365))} years`;
    if (seconds < 86400 * 365 * 1e6) {
      const thousands = Math.round(seconds / (86400 * 365 * 1000));
      return `${thousands.toLocaleString()} thousand years`;
    }
    if (seconds < 86400 * 365 * 1e9) {
      const millions = (seconds / (86400 * 365 * 1e6)).toFixed(1);
      return `${millions} million years`;
    }
    if (seconds < 86400 * 365 * 1e12) {
      const billions = (seconds / (86400 * 365 * 1e9)).toFixed(1);
      return `${billions} billion years`;
    }
    return 'Trillions of years (Beyond Universe age)';
  }

  /**
   * Calculate crack times for all threat models
   */
  function estimateCrackTimes(effectiveEntropy) {
    // Average guesses needed is 50% of the key space (2^(entropy - 1))
    const totalPossibilities = Math.pow(2, effectiveEntropy);
    const averageGuesses = totalPossibilities / 2;

    const results = {};
    for (const [key, model] of Object.entries(ATTACK_MODELS)) {
      const seconds = averageGuesses / model.rate;
      results[key] = {
        name: model.name,
        desc: model.desc,
        seconds: seconds,
        formatted: formatCrackTime(seconds)
      };
    }

    return results;
  }

  /**
   * Classify strength score and label
   */
  function getStrengthTier(effectiveEntropy, str, patterns) {
    if (!str || str.length === 0) {
      return {
        level: 0,
        score: 0,
        label: 'Enter a Password',
        color: '#64748b',
        gradient: 'from-slate-600 to-slate-500',
        summary: 'Type anything above to inspect its cryptographic resilience.'
      };
    }

    // Critical breached password check override
    if (patterns && patterns.patterns && patterns.patterns.some(p => p.critical)) {
      return {
        level: 1,
        score: 10,
        label: 'Severely Compromised',
        color: '#ef4444',
        gradient: 'from-red-600 to-rose-500',
        summary: 'This password appears in millions of leaked databases. Attackers test this immediately!'
      };
    }

    if (effectiveEntropy < 28) {
      return {
        level: 1,
        score: Math.min(25, Math.max(12, Math.round(effectiveEntropy * 0.9))),
        label: 'Very Weak',
        color: '#ef4444',
        gradient: 'from-red-500 to-amber-600',
        summary: 'Easily guessed by botnets in seconds using basic dictionaries.'
      };
    } else if (effectiveEntropy < 46) {
      return {
        level: 2,
        score: Math.round(25 + ((effectiveEntropy - 28) / (46 - 28)) * 25),
        label: 'Weak / Moderate',
        color: '#f59e0b',
        gradient: 'from-amber-500 to-yellow-500',
        summary: 'Resists casual guessing, but vulnerable to fast offline GPU cracking.'
      };
    } else if (effectiveEntropy < 65) {
      return {
        level: 3,
        score: Math.round(50 + ((effectiveEntropy - 46) / (65 - 46)) * 25),
        label: 'Good / Decent',
        color: '#3b82f6',
        gradient: 'from-sky-500 to-blue-600',
        summary: 'Solid resistance for everyday accounts. Highly secure against online attacks.'
      };
    } else if (effectiveEntropy < 85) {
      return {
        level: 4,
        score: Math.round(75 + ((effectiveEntropy - 65) / (85 - 65)) * 20),
        label: 'Strong',
        color: '#10b981',
        gradient: 'from-emerald-500 to-teal-500',
        summary: 'Excellent security! Exponentially hard to crack even with dedicated supercomputers.'
      };
    } else {
      return {
        level: 5,
        score: 100,
        label: 'Ultra Fortress',
        color: '#8b5cf6',
        gradient: 'from-purple-500 via-indigo-500 to-emerald-400',
        summary: 'Cryptographically formidable! Would take trillions of years to brute-force.'
      };
    }
  }

  return {
    calculateEntropy,
    estimateCrackTimes,
    getStrengthTier
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = EntropyCalc;
}
