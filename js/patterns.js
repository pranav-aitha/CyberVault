/**
 * Password Pattern Detection & Heuristics Engine
 * Detects common vulnerabilities beyond simple character counts:
 * - Keyboard walks (rows, columns, reverse)
 * - Dictionary and common weak passwords
 * - Leetspeak transformations
 * - Sequences and repetitions
 * - Date and year attachments
 * - Multi-word passphrase identification
 */

const Patterns = (function () {
  // Top common weak passwords & roots
  const COMMON_PASSWORDS = new Set([
    'password', '123456', '123456789', 'guest', 'qwerty', '12345678', '111111',
    '12345', '1234567', 'dragon', 'welcome', 'monkey', 'password1', 'football',
    'master', 'sunshine', 'princess', 'solo', 'admin', 'iloveyou', 'starwars',
    'superman', 'trustno1', 'secret', 'charlie', 'shadow', 'michael', 'jordan',
    'harley', 'batman', 'killer', 'liverpool', 'arsenal', 'chelsea', 'freedom',
    'mustang', 'letmein', 'access', 'default', 'pass123', 'computer', 'orange',
    'coffee', 'winner', 'testing', 'robert', 'thomas', 'hockey', 'soccer',
    'baseball', 'monster', 'hunter', 'hunter2', 'bailey', 'yellow', 'purple',
    'summer', 'winter', 'spring', 'autumn', 'london', 'boston', 'matrix',
    'cheese', 'cookie', 'pepper', 'ginger', 'buster', 'prince', 'diamond'
  ]);

  // Keyboard physical layouts
  const QWERTY_ROWS = [
    '`1234567890-=',
    'qwertyuiop[]\\',
    "asdfghjkl;'",
    'zxcvbnm,./'
  ];

  const QWERTY_COLS = [
    '`1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik,', '9ol.', '0p;/', '-[\'', '=]\\\\'
  ];

  const NUMPAD_WALKS = [
    '789', '456', '123', '0.',
    '7410', '8520', '963.', '753', '951', '159', '357'
  ];

  // Leet mappings for normalization
  const LEET_MAP = {
    '@': 'a', '4': 'a', '^': 'a',
    '8': 'b',
    '(': 'c', '<': 'c', '{': 'c',
    '3': 'e', '€': 'e',
    '9': 'g',
    '#': 'h',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '$': 's', '5': 's',
    '7': 't', '+': 't',
    '2': 'z', '%': 'z'
  };

  /**
   * Decode leetspeak to base text
   */
  function decodeLeet(str) {
    let result = '';
    for (const char of str.toLowerCase()) {
      result += LEET_MAP[char] || char;
    }
    return result;
  }

  /**
   * Detect keyboard walks (qwerty, asdf, 1qaz, 12345, etc.)
   * Finds maximal contiguous sequences along rows and columns.
   */
  function detectKeyboardWalks(str) {
    const lower = str.toLowerCase();
    const walks = [];

    function findMaximalWalks(gridList, walkType) {
      for (const line of gridList) {
        const revLine = line.split('').reverse().join('');
        const linesToCheck = [line, revLine];

        for (const targetLine of linesToCheck) {
          // Find longest matching substrings of length >= 4
          for (let len = Math.min(targetLine.length, lower.length); len >= 4; len--) {
            for (let i = 0; i <= lower.length - len; i++) {
              const sub = lower.substr(i, len);
              if (targetLine.includes(sub)) {
                // Check if this region is already covered by a longer walk
                const alreadyCovered = walks.some(w => 
                  w.type === walkType && w.match.includes(sub)
                );
                if (!alreadyCovered) {
                  walks.push({
                    type: walkType,
                    match: sub,
                    start: i,
                    length: len,
                    explanation: `Keyboard walk detected ("${sub}"). Attack dictionaries prioritize keyboard layout trajectories.`
                  });
                }
              }
            }
          }
        }
      }
    }

    findMaximalWalks(QWERTY_ROWS, 'Keyboard row walk');
    findMaximalWalks(QWERTY_COLS, 'Keyboard column walk');
    findMaximalWalks(NUMPAD_WALKS, 'Numpad pattern');

    return deduplicateMatches(walks);
  }

  /**
   * Detect alphabetical, numeric, or ASCII sequences
   */
  function detectSequences(str) {
    const matches = [];
    const lower = str.toLowerCase();

    let seqCount = 1;
    let seqDir = 0; // 1 for ascending, -1 for descending

    for (let i = 1; i < lower.length; i++) {
      const diff = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
      if (diff === 1 || diff === -1) {
        if (seqDir === 0 || seqDir === diff) {
          seqCount++;
          seqDir = diff;
        } else {
          if (seqCount >= 3) {
            const sub = str.substr(i - seqCount, seqCount);
            matches.push({
              type: 'Sequence',
              match: sub,
              length: seqCount,
              explanation: `Predictable sequence "${sub}". Attack rules automatically test sequential characters.`
            });
          }
          seqCount = 2;
          seqDir = diff;
        }
      } else {
        if (seqCount >= 3) {
          const sub = str.substr(i - seqCount, seqCount);
          matches.push({
            type: 'Sequence',
            match: sub,
            length: seqCount,
            explanation: `Predictable sequence "${sub}". Attack rules automatically test sequential characters.`
          });
        }
        seqCount = 1;
        seqDir = 0;
      }
    }

    if (seqCount >= 3) {
      const sub = str.substr(str.length - seqCount, seqCount);
      matches.push({
        type: 'Sequence',
        match: sub,
        length: seqCount,
        explanation: `Predictable sequence "${sub}". Attack rules automatically test sequential characters.`
      });
    }

    return deduplicateMatches(matches);
  }

  /**
   * Detect repeated characters or repeated substrings
   */
  function detectRepeats(str) {
    const matches = [];

    // Single repeated characters: "aaaa", "11111"
    const charRepeatRegex = /(.)\1{2,}/g;
    let match;
    while ((match = charRepeatRegex.exec(str)) !== null) {
      matches.push({
        type: 'Character repetition',
        match: match[0],
        length: match[0].length,
        explanation: `Repeated character "${match[0]}". Adds almost zero cryptographic entropy.`
      });
    }

    // Repeated chunks: "abcabc", "passpass"
    for (let len = 2; len <= Math.floor(str.length / 2); len++) {
      for (let i = 0; i <= str.length - (len * 2); i++) {
        const chunk = str.substr(i, len);
        const nextChunk = str.substr(i + len, len);
        if (chunk.toLowerCase() === nextChunk.toLowerCase()) {
          matches.push({
            type: 'Chunk repetition',
            match: chunk + nextChunk,
            length: len * 2,
            explanation: `Repeated phrase pattern "${chunk + nextChunk}". Attackers compress repeated tokens.`
          });
        }
      }
    }

    return deduplicateMatches(matches);
  }

  /**
   * Detect dates or year patterns
   */
  function detectDates(str) {
    const matches = [];

    // Years 1900 - 2099
    const yearRegex = /\b(19\d{2}|20\d{2})\b/g;
    let match;
    while ((match = yearRegex.exec(str)) !== null) {
      matches.push({
        type: 'Year pattern',
        match: match[0],
        length: 4,
        explanation: `Year "${match[0]}" detected. Attackers always append birth years and current years.`
      });
    }

    // Common date formats (e.g. 12051998, 19950821, 01-01-2000)
    const dateRegex = /(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})|(\d{8})/g;
    while ((match = dateRegex.exec(str)) !== null) {
      // Avoid duplicate if it's already caught as a simple sequence or single year
      if (match[0].length >= 6) {
        matches.push({
          type: 'Date pattern',
          match: match[0],
          length: match[0].length,
          explanation: `Date-like sequence "${match[0]}". Personal dates are top targets in targeted social engineering attacks.`
        });
      }
    }

    return deduplicateMatches(matches);
  }

  /**
   * Detect dictionary words or common passwords (including leet-decoded)
   */
  function detectDictionaryWords(str) {
    const matches = [];
    const lower = str.toLowerCase();
    const deLeeted = decodeLeet(lower);

    // Direct check in common passwords
    if (COMMON_PASSWORDS.has(lower)) {
      matches.push({
        type: 'Breached/Top Password',
        match: str,
        length: str.length,
        critical: true,
        explanation: `"${str}" is in the top 100 most breached passwords in history. Cracked in under 0.001 seconds!`
      });
    }

    // Check substring matches of dictionary words
    for (const word of COMMON_PASSWORDS) {
      if (word.length >= 4) {
        if (lower.includes(word) && lower !== word) {
          matches.push({
            type: 'Common word stem',
            match: word,
            length: word.length,
            explanation: `Contains common dictionary word "${word}". Rule-based attacks mutate dictionary words rapidly.`
          });
        } else if (deLeeted.includes(word) && !lower.includes(word)) {
          matches.push({
            type: 'Leetspeak substitution',
            match: word,
            length: word.length,
            explanation: `Substitutes symbols for "${word}" (e.g. @ for a, 0 for o). Modern cracking tools easily undo leetspeak in microseconds.`
          });
        }
      }
    }

    return deduplicateMatches(matches);
  }

  /**
   * Detect if the password is structured as a Passphrase (e.g., 3-6 distinct words)
   */
  function analyzePassphrase(str) {
    // Delimiters: spaces, dashes, dots, underscores
    const delimiters = /[\s\-_.]+/;
    const tokens = str.split(delimiters).filter(t => t.length > 0);

    // Also check camelCase/PascalCase: "CorrectHorseBatteryStaple"
    const camelTokens = str.replace(/([a-z])([A-Z])/g, '$1 $2').split(' ');

    const candidateTokens = tokens.length >= 3 ? tokens : (camelTokens.length >= 3 ? camelTokens : []);

    if (candidateTokens.length >= 3 && str.length >= 15) {
      const allWords = candidateTokens.every(t => /^[a-zA-Z0-9]+$/.test(t) && t.length >= 2);
      if (allWords) {
        return {
          isPassphrase: true,
          wordCount: candidateTokens.length,
          tokens: candidateTokens,
          explanation: `Strong passphrase detected (${candidateTokens.length} words, ${str.length} characters). Passphrases provide astronomical search spaces while staying easy for humans to remember!`
        };
      }
    }

    return {
      isPassphrase: false,
      wordCount: candidateTokens.length,
      tokens: []
    };
  }

  /**
   * Helper to deduplicate pattern overlaps
   */
  function deduplicateMatches(matches) {
    const seen = new Set();
    const result = [];
    for (const m of matches) {
      const key = `${m.type}:${m.match.toLowerCase()}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push(m);
      }
    }
    return result;
  }

  /**
   * Master analysis function for patterns
   */
  function analyze(str) {
    if (!str || str.length === 0) {
      return {
        patterns: [],
        passphrase: { isPassphrase: false },
        scorePenalty: 0
      };
    }

    const keyboardWalks = detectKeyboardWalks(str);
    const sequences = detectSequences(str);
    const repeats = detectRepeats(str);
    const dates = detectDates(str);
    const dictionary = detectDictionaryWords(str);
    const passphrase = analyzePassphrase(str);

    const allPatterns = [
      ...dictionary,
      ...keyboardWalks,
      ...sequences,
      ...repeats,
      ...dates
    ];

    // Calculate score penalty based on found weaknesses
    let penalty = 0;
    allPatterns.forEach(p => {
      if (p.critical) penalty += 40;
      else if (p.type.includes('Dictionary') || p.type.includes('word')) penalty += 20;
      else if (p.type.includes('walk')) penalty += 15;
      else if (p.type.includes('Sequence') || p.type.includes('repetition')) penalty += 10;
      else if (p.type.includes('Date')) penalty += 12;
      else penalty += 5;
    });

    return {
      patterns: allPatterns,
      passphrase: passphrase,
      scorePenalty: Math.min(penalty, 60)
    };
  }

  return {
    analyze,
    decodeLeet
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Patterns;
}
