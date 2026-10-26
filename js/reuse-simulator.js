/**
 * Password Reuse & Credential Stuffing Simulator
 * Demonstrates the ripple effect of data breaches across reused accounts
 * and explains k-Anonymity for breach lookup privacy.
 */

const ReuseSimulator = (function () {
  const DEFAULT_ACCOUNTS = [
    {
      id: 'gaming_forum',
      name: 'Indie Gaming Forum',
      category: 'Low Security / Community',
      icon: 'gamepad-2',
      securityLevel: 'Low (Poorly salted MD5)',
      breachedFirst: true,
      reused: true,
      has2FA: false,
      consequence: 'Database compromised via SQL injection. Attacker dumps email and password combination.'
    },
    {
      id: 'online_store',
      name: 'MegaShop Retail',
      category: 'E-Commerce / Shopping',
      icon: 'shopping-bag',
      securityLevel: 'Medium',
      breachedFirst: false,
      reused: true,
      has2FA: false,
      consequence: 'Unauthorized purchases made; saved credit card details and home address accessed.'
    },
    {
      id: 'primary_email',
      name: 'Primary Email Account',
      category: 'Master Identity Hub',
      icon: 'mail',
      securityLevel: 'High',
      breachedFirst: false,
      reused: true,
      has2FA: false,
      consequence: 'CRITICAL! Attacker has inbox access and can trigger "Password Reset" on any other service.'
    },
    {
      id: 'bank_account',
      name: 'Online Banking Portal',
      category: 'Financial Services',
      icon: 'shield-alert',
      securityLevel: 'High',
      breachedFirst: false,
      reused: true,
      has2FA: true,
      consequence: 'Targeted for wire fraud; sensitive financial statements and account balance vulnerable.'
    }
  ];

  /**
   * Run the Credential Stuffing attack simulation step-by-step
   */
  async function runSimulation(accounts, onStepUpdate) {
    const results = [];

    // Step 1: Initial breach of Forum
    const initialSite = accounts[0];
    results.push({
      step: 1,
      siteId: initialSite.id,
      status: 'breached',
      title: `${initialSite.name} suffers a zero-day breach`,
      detail: `Attackers exploit a legacy forum plugin and extract the database containing your credentials.`,
      severity: 'high'
    });
    if (onStepUpdate) onStepUpdate(results[results.length - 1]);
    await wait(900);

    // Step 2: Credential Stuffing Botnet activated
    results.push({
      step: 2,
      siteId: null,
      status: 'botnet_active',
      title: 'Automated Botnet runs Credential Stuffing',
      detail: `A high-speed bot pipeline distributes the leaked email/password pair against thousands of top web services in parallel.`,
      severity: 'warning'
    });
    if (onStepUpdate) onStepUpdate(results[results.length - 1]);
    await wait(900);

    // Step 3..N: Subsequent targets
    for (let i = 1; i < accounts.length; i++) {
      const acc = accounts[i];
      let outcome = '';
      let status = '';
      let severity = '';

      if (!acc.reused) {
        // Unique password
        outcome = `BLOCKED: Password rejected! Because you used a unique password for ${acc.name}, the credential stuffing attempt failed completely.`;
        status = 'safe';
        severity = 'success';
      } else if (acc.has2FA) {
        // Reused but 2FA saved the day
        outcome = `DEFENDED BY 2FA: Credentials matched, but the attacker was blocked by the Two-Factor Authentication prompt on your phone!`;
        status = 'defended';
        severity = 'info';
      } else {
        // Full takeover
        outcome = `COMPROMISED! ${acc.name} was successfully breached using the recycled password. ${acc.consequence}`;
        status = 'compromised';
        severity = 'danger';
      }

      results.push({
        step: i + 2,
        siteId: acc.id,
        status: status,
        title: `Testing: ${acc.name}`,
        detail: outcome,
        severity: severity
      });

      if (onStepUpdate) onStepUpdate(results[results.length - 1]);
      await wait(1000);
    }

    return results;
  }

  /**
   * k-Anonymity calculation for safe breach lookup demonstration
   */
  async function computeKAnonymitySteps(password) {
    // 1. Calculate SHA-1
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await window.crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fullHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    // 2. Split into prefix (first 5 chars) and suffix (remaining 35 chars)
    const prefix = fullHash.substring(0, 5);
    const suffix = fullHash.substring(5);

    return {
      password,
      fullHash,
      prefix,
      suffix,
      explanation: `Only the 5-character prefix "${prefix}" is sent to the breach server. The server responds with ~500 possible matching suffixes. Your browser compares "${suffix}" locally in your RAM. The server NEVER knows what your actual password or remaining hash was!`
    };
  }

  function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  return {
    DEFAULT_ACCOUNTS,
    runSimulation,
    computeKAnonymitySteps
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReuseSimulator;
}
