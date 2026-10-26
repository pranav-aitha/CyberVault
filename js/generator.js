/**
 * Secure Password & Passphrase Generator
 * Supports Diceware-style memorable passphrases and cryptographically strong random strings.
 */

const Generator = (function () {
  const WORDLIST = [
    'amber', 'anchor', 'apollo', 'arctic', 'arrow', 'atlas', 'autumn', 'beacon',
    'breeze', 'bronze', 'canyon', 'cedar', 'cipher', 'clover', 'cobalt', 'comet',
    'copper', 'cosmic', 'crater', 'crystal', 'delta', 'desert', 'diamond', 'drifter',
    'eagle', 'echo', 'ember', 'emerald', 'falcon', 'feather', 'fable', 'flame',
    'forest', 'fossil', 'galaxy', 'garnet', 'glacier', 'granite', 'harbor', 'haven',
    'hawk', 'hazel', 'horizon', 'hunter', 'hybrid', 'island', 'jasper', 'journey',
    'jungle', 'jupiter', 'lagoon', 'lantern', 'legend', 'lotus', 'lunar', 'magnet',
    'marble', 'meadow', 'meteor', 'mirage', 'monarch', 'moonlight', 'nebula', 'nexus',
    'nomad', 'oasis', 'ocean', 'olive', 'omega', 'onyx', 'orbit', 'orchid',
    'panther', 'pebble', 'phoenix', 'pioneer', 'planet', 'plasma', 'polar', 'prism',
    'pulse', 'pyramid', 'quantum', 'quartz', 'radar', 'radiant', 'rainbow', 'raven',
    'relic', 'ripple', 'river', 'rocket', 'rover', 'ruby', 'safari', 'sapphire',
    'shadow', 'shield', 'sierra', 'silver', 'solar', 'spark', 'sphere', 'spiral',
    'spring', 'starling', 'stellar', 'summit', 'sunrise', 'sunset', 'thunder', 'timber',
    'titan', 'topaz', 'torrent', 'tracker', 'trident', 'tropic', 'tundra', 'twilight',
    'valley', 'vapor', 'velvet', 'venture', 'vessel', 'violet', 'vortex', 'voyage',
    'walnut', 'wander', 'wave', 'whisper', 'willow', 'winter', 'zenith', 'zephyr'
  ];

  /**
   * Cryptographically secure random integer in range [0, max)
   */
  function secureRandomInt(max) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return array[0] % max;
  }

  /**
   * Generate a multi-word passphrase
   */
  function generatePassphrase(options = {}) {
    const wordCount = options.wordCount || 4;
    const separator = options.separator !== undefined ? options.separator : '-';
    const capitalize = options.capitalize !== undefined ? options.capitalize : false;
    const addNumber = options.addNumber !== undefined ? options.addNumber : true;

    const words = [];
    for (let i = 0; i < wordCount; i++) {
      let word = WORDLIST[secureRandomInt(WORDLIST.length)];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      words.push(word);
    }

    if (addNumber) {
      const num = secureRandomInt(90) + 10; // 2-digit number 10-99
      words[words.length - 1] += num;
    }

    return words.join(separator);
  }

  /**
   * Generate a high-entropy random character password
   */
  function generateRandomPassword(length = 16, includeSymbols = true) {
    const lowers = 'abcdefghijklmnopqrstuvwxyz';
    const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{}<>?';

    let pool = lowers + uppers + numbers;
    if (includeSymbols) pool += symbols;

    // Ensure at least one of each required set
    let result = [
      lowers[secureRandomInt(lowers.length)],
      uppers[secureRandomInt(uppers.length)],
      numbers[secureRandomInt(numbers.length)]
    ];
    if (includeSymbols) {
      result.push(symbols[secureRandomInt(symbols.length)]);
    }

    while (result.length < length) {
      result.push(pool[secureRandomInt(pool.length)]);
    }

    // Shuffle using Fisher-Yates with crypto random
    for (let i = result.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join('');
  }

  return {
    generatePassphrase,
    generateRandomPassword
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Generator;
}
