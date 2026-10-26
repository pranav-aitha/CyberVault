/**
 * CyberVault - Main Application Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize canvas confetti
  Confetti.init();

  // Elements - Tabs
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  // Elements - Inspector
  const pwdInput = document.getElementById('password-input');
  const inputContainer = document.getElementById('input-container');
  const btnToggleVis = document.getElementById('btn-toggle-vis');
  const iconEye = document.getElementById('icon-eye');
  const btnCopyPwd = document.getElementById('btn-copy-pwd');
  const btnSamplePwd = document.getElementById('btn-sample-pwd');
  const btnClearPwd = document.getElementById('btn-clear-pwd');

  // Elements - Meter & Metrics
  const strengthBadge = document.getElementById('strength-badge');
  const entropyBadge = document.getElementById('entropy-badge');
  const scoreVal = document.getElementById('score-val');
  const meterFeedback = document.getElementById('meter-feedback');
  const segments = [
    document.getElementById('seg-1'),
    document.getElementById('seg-2'),
    document.getElementById('seg-3'),
    document.getElementById('seg-4'),
    document.getElementById('seg-5')
  ];

  const metricLen = document.getElementById('metric-len');
  const metricPool = document.getElementById('metric-pool');
  const metricDiversity = document.getElementById('metric-diversity');
  const metricTypes = document.getElementById('metric-types');
  const metricEntropy = document.getElementById('metric-entropy');
  const metricEntropyType = document.getElementById('metric-entropy-type');
  const metricCrackTime = document.getElementById('metric-crack-time');

  const flagLower = document.getElementById('flag-lower');
  const flagUpper = document.getElementById('flag-upper');
  const flagDigits = document.getElementById('flag-digits');
  const flagSymbols = document.getElementById('flag-symbols');

  const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
  const recommendationsList = document.getElementById('recommendations-list');

  const timeOnlineThrottled = document.getElementById('time-online-throttled');
  const timeOnlineFast = document.getElementById('time-online-fast');
  const timeOfflineSlow = document.getElementById('time-offline-slow');
  const timeOfflineFast = document.getElementById('time-offline-fast');

  // Elements - Crypto Lab
  const labPwdInput = document.getElementById('lab-pwd-input');
  const btnRollSalt = document.getElementById('btn-roll-salt');
  const labRawHash = document.getElementById('lab-raw-hash');
  const labSaltVal = document.getElementById('lab-salt-val');
  const labSaltedHash = document.getElementById('lab-salted-hash');
  const labPepperedHash = document.getElementById('lab-peppered-hash');
  const twinPwdLabel = document.getElementById('twin-pwd-label');
  const aliceSalt = document.getElementById('alice-salt');
  const aliceHash = document.getElementById('alice-hash');
  const bobSalt = document.getElementById('bob-salt');
  const bobHash = document.getElementById('bob-hash');

  // Elements - Simulator
  const accountsGrid = document.getElementById('accounts-grid');
  const btnStartSim = document.getElementById('btn-start-sim');
  const btnResetSim = document.getElementById('btn-reset-sim');
  const simTimeline = document.getElementById('sim-timeline');
  const btnDemoKanon = document.getElementById('btn-demo-kanon');
  const kanonDemoOutput = document.getElementById('kanon-demo-output');

  // Elements - Generator
  const genOutput = document.getElementById('gen-output');
  const genEntropyVal = document.getElementById('gen-entropy-val');
  const genCrackVal = document.getElementById('gen-crack-val');
  const radioPassphrase = document.getElementById('radio-passphrase');
  const radioRandom = document.getElementById('radio-random');
  const sliderWords = document.getElementById('slider-words');
  const labelWordCount = document.getElementById('label-word-count');
  const chkCapitalize = document.getElementById('chk-capitalize');
  const chkNumber = document.getElementById('chk-number');
  const selectSeparator = document.getElementById('select-separator');
  const btnRegen = document.getElementById('btn-regen');
  const btnCopyGen = document.getElementById('btn-copy-gen');
  const btnTestInInspector = document.getElementById('btn-test-in-inspector');
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toast-msg');

  // State
  let currentSalt = CryptoLab.generateRandomSalt(12);
  const SERVER_PEPPER = '0x_SECURE_HSM_PEPPER_SEED_9942A';
  let lastTierLevel = 0;

  let simulationAccounts = JSON.parse(JSON.stringify(ReuseSimulator.DEFAULT_ACCOUNTS));
  let isSimulating = false;

  const SAMPLE_PASSWORDS = [
    '123456',
    'qwerty2024!',
    'p@ssw0rd',
    'Tr0ub4dor&3',
    'correct-horse-battery-staple',
    'velvet-granite-nebula-falcon-42'
  ];
  let sampleIndex = 0;

  // -------------------------------------------------------------
  // Tab Navigation
  // -------------------------------------------------------------
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });

  // -------------------------------------------------------------
  // Toast Helper
  // -------------------------------------------------------------
  function showToast(message) {
    toastMsg.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2400);
  }

  // -------------------------------------------------------------
  // TAB 1: Vault Inspector Logic
  // -------------------------------------------------------------
  function evaluatePassword(pwd) {
    if (!pwd || pwd.length === 0) {
      resetInspectorUI();
      lastTierLevel = 0;
      return;
    }

    const patternResults = Patterns.analyze(pwd);
    const entropyResults = EntropyCalc.calculateEntropy(pwd, patternResults);
    const crackTimes = EntropyCalc.estimateCrackTimes(entropyResults.effectiveEntropy);
    const tier = EntropyCalc.getStrengthTier(entropyResults.effectiveEntropy, pwd, patternResults);

    // Micro-animations:
    // 1. Confetti on hitting Strong or Fortress
    if ((tier.level === 4 || tier.level === 5) && lastTierLevel < 4) {
      Confetti.trigger(70);
    }
    // 2. Shake animation on critical weak or breached pattern
    if (patternResults.patterns.some(p => p.critical)) {
      inputContainer.classList.add('shake');
      setTimeout(() => inputContainer.classList.remove('shake'), 500);
    }
    lastTierLevel = tier.level;

    // Update Meter Badge & Segments
    strengthBadge.textContent = tier.label;
    strengthBadge.style.backgroundColor = `${tier.color}25`;
    strengthBadge.style.color = tier.color;
    strengthBadge.style.border = `1px solid ${tier.color}60`;

    entropyBadge.textContent = `${entropyResults.effectiveEntropy} bits effective`;
    scoreVal.textContent = tier.score;
    meterFeedback.textContent = tier.summary;

    // Update Segments
    segments.forEach((seg, index) => {
      if (index < tier.level) {
        seg.className = 'meter-seg active';
        seg.style.backgroundColor = tier.color;
        seg.style.color = tier.color;
      } else {
        seg.className = 'meter-seg';
        seg.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';
        seg.style.boxShadow = 'none';
      }
    });

    // Update Metric Cards
    metricLen.textContent = `${pwd.length} chars`;
    metricPool.textContent = `Charset pool: ${entropyResults.poolSize} symbols`;

    const { hasLower, hasUpper, hasDigits, hasSpecial } = entropyResults.charFlags;
    flagLower.style.opacity = hasLower ? '1' : '0.25';
    flagLower.style.color = hasLower ? '#67e8f9' : '';
    flagUpper.style.opacity = hasUpper ? '1' : '0.25';
    flagUpper.style.color = hasUpper ? '#a5b4fc' : '';
    flagDigits.style.opacity = hasDigits ? '1' : '0.25';
    flagDigits.style.color = hasDigits ? '#fcd34d' : '';
    flagSymbols.style.opacity = hasSpecial ? '1' : '0.25';
    flagSymbols.style.color = hasSpecial ? '#f472b6' : '';

    const typeCount = [hasLower, hasUpper, hasDigits, hasSpecial].filter(Boolean).length;
    metricTypes.textContent = `${typeCount} of 4 character types`;

    metricEntropy.textContent = `${entropyResults.effectiveEntropy} bits`;
    metricEntropyType.textContent = patternResults.passphrase.isPassphrase 
      ? 'Passphrase mode (Diceware)' 
      : `Raw: ${entropyResults.rawEntropy} bits`;

    metricCrackTime.textContent = crackTimes.offlineFast.formatted;
    metricCrackTime.style.color = tier.color;

    // Update Crack Time Matrix
    timeOnlineThrottled.textContent = crackTimes.onlineThrottled.formatted;
    timeOnlineFast.textContent = crackTimes.onlineFast.formatted;
    timeOfflineSlow.textContent = crackTimes.offlineSlow.formatted;
    timeOfflineFast.textContent = crackTimes.offlineFast.formatted;

    // Render Diagnostic Lists
    renderDiagnostics(pwd, patternResults, entropyResults, tier);
  }

  function resetInspectorUI() {
    strengthBadge.textContent = 'Enter a Password';
    strengthBadge.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
    strengthBadge.style.color = 'var(--text-muted)';
    strengthBadge.style.border = '1px solid rgba(255, 255, 255, 0.1)';

    entropyBadge.textContent = '0 bits entropy';
    scoreVal.textContent = '0';
    meterFeedback.textContent = 'Type anything above to inspect its cryptographic resilience.';

    segments.forEach(seg => {
      seg.className = 'meter-seg';
      seg.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';
      seg.style.boxShadow = 'none';
    });

    metricLen.textContent = '0 chars';
    metricPool.textContent = 'Charset pool: 0 symbols';
    metricTypes.textContent = '0 of 4 character types';
    [flagLower, flagUpper, flagDigits, flagSymbols].forEach(f => f.style.opacity = '0.25');

    metricEntropy.textContent = '0.0 bits';
    metricEntropyType.textContent = 'Information density';
    metricCrackTime.textContent = 'Instant';
    metricCrackTime.style.color = 'var(--accent-rose)';

    timeOnlineThrottled.textContent = 'Instant';
    timeOnlineFast.textContent = 'Instant';
    timeOfflineSlow.textContent = 'Instant';
    timeOfflineFast.textContent = 'Instant';

    vulnerabilitiesList.innerHTML = `
      <div class="diagnostic-item info">
        <div>
          <div class="diag-title">Awaiting Input</div>
          <div class="diag-desc">Type a password above to scan for keyboard walks, common words, predictable numbers, and leaked sequences.</div>
        </div>
      </div>
    `;

    recommendationsList.innerHTML = `
      <div class="diagnostic-item info">
        <div>
          <div class="diag-title">Smart Guidance Ready</div>
          <div class="diag-desc">We will provide clear, non-generic advice on making your password astronomically harder to crack.</div>
        </div>
      </div>
    `;
  }

  function renderDiagnostics(pwd, patternResults, entropyResults, tier) {
    // 1. Weaknesses List
    const weaknesses = [];

    if (patternResults.patterns.length > 0) {
      patternResults.patterns.forEach(pat => {
        weaknesses.push({
          severity: pat.critical ? 'danger' : 'warning',
          title: pat.type,
          desc: pat.explanation
        });
      });
    }

    if (pwd.length < 10) {
      weaknesses.push({
        severity: 'danger',
        title: 'Short Length (< 10 characters)',
        desc: `At ${pwd.length} characters, search spaces are small enough for consumer GPUs to exhaust in seconds through sheer brute-force.`
      });
    }

    if (weaknesses.length === 0) {
      vulnerabilitiesList.innerHTML = `
        <div class="diagnostic-item success">
          <div>
            <div class="diag-title">Zero Obvious Patterns Detected!</div>
            <div class="diag-desc">No dictionary words, no keyboard walks, no sequences, and no common date suffixes found.</div>
          </div>
        </div>
      `;
    } else {
      vulnerabilitiesList.innerHTML = weaknesses.map(w => `
        <div class="diagnostic-item ${w.severity}">
          <div>
            <div class="diag-title">${escapeHtml(w.title)}</div>
            <div class="diag-desc">${escapeHtml(w.desc)}</div>
          </div>
        </div>
      `).join('');
    }

    // 2. Strengths & Smart Advice List
    const advices = [];

    if (patternResults.passphrase && patternResults.passphrase.isPassphrase) {
      advices.push({
        severity: 'success',
        title: 'Passphrase Advantage',
        desc: `You are using a multi-word passphrase (${patternResults.passphrase.wordCount} words)! This gives massive length without needing unmemorable random characters.`
      });
    } else if (pwd.length >= 16) {
      advices.push({
        severity: 'success',
        title: 'Substantial Length (16+ chars)',
        desc: 'Length exponentially dominates character complexity. Doubling password length squares attacker brute-force attempts!'
      });
    }

    if (entropyResults.charFlags.hasSpecial) {
      advices.push({
        severity: 'info',
        title: 'Extended Character Pool',
        desc: 'Including symbols expanded your character pool to ~95 potential characters per position.'
      });
    }

    // Educational advice for improvement (not just "add a symbol")
    if (!patternResults.passphrase.isPassphrase && pwd.length < 16) {
      advices.push({
        severity: 'info',
        title: 'Try the Passphrase Method',
        desc: 'Instead of memorizing cryptic symbols like "P@$$w0rd123!", join 4 random memorable words together (e.g. "velvet-cobalt-orbit-haven"). It is easier to remember, impossible to guess, and yields 50+ bits of true entropy!'
      });
    }

    if (tier.level < 4) {
      advices.push({
        severity: 'warning',
        title: 'Avoid Common Suffix Traps',
        desc: 'Placing "!" or "123" at the very end of an ordinary word is the first rule cracked by password auditing tools like Hashcat.'
      });
    }

    recommendationsList.innerHTML = advices.map(a => `
      <div class="diagnostic-item ${a.severity}">
        <div>
          <div class="diag-title">${escapeHtml(a.title)}</div>
          <div class="diag-desc">${escapeHtml(a.desc)}</div>
        </div>
      </div>
    `).join('');
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Input event
  pwdInput.addEventListener('input', (e) => {
    evaluatePassword(e.target.value);
  });

  // Toggle Visibility
  btnToggleVis.addEventListener('click', () => {
    const isPass = pwdInput.type === 'password';
    pwdInput.type = isPass ? 'text' : 'password';
    iconEye.innerHTML = isPass 
      ? '<path d="m17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
      : '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>';
  });

  // Copy password
  btnCopyPwd.addEventListener('click', () => {
    if (!pwdInput.value) return;
    navigator.clipboard.writeText(pwdInput.value);
    showToast('Password copied to clipboard!');
  });

  // Sample roll
  btnSamplePwd.addEventListener('click', () => {
    pwdInput.value = SAMPLE_PASSWORDS[sampleIndex];
    sampleIndex = (sampleIndex + 1) % SAMPLE_PASSWORDS.length;
    evaluatePassword(pwdInput.value);
  });

  // Clear password
  btnClearPwd.addEventListener('click', () => {
    pwdInput.value = '';
    evaluatePassword('');
    pwdInput.focus();
  });

  // -------------------------------------------------------------
  // TAB 2: Crypto Lab Logic
  // -------------------------------------------------------------
  async function updateCryptoLab() {
    const pwd = labPwdInput.value || 'hunter2';
    twinPwdLabel.textContent = pwd;

    // 1. Pipeline for current password
    const pipeline = await CryptoLab.computeCryptoPipeline(pwd, currentSalt, SERVER_PEPPER);
    labRawHash.textContent = pipeline.raw.hash;
    labSaltVal.textContent = currentSalt;
    labSaltedHash.textContent = pipeline.salted.hash;
    labPepperedHash.textContent = pipeline.peppered.hash;

    // 2. Twin comparison (Alice vs Bob)
    const twins = await CryptoLab.compareTwinUsers(pwd, SERVER_PEPPER);
    aliceSalt.textContent = twins.userA.salt;
    aliceHash.textContent = twins.userA.saltedHash;
    bobSalt.textContent = twins.userB.salt;
    bobHash.textContent = twins.userB.saltedHash;
  }

  labPwdInput.addEventListener('input', () => {
    updateCryptoLab();
  });

  btnRollSalt.addEventListener('click', () => {
    currentSalt = CryptoLab.generateRandomSalt(12);
    updateCryptoLab();
    showToast('Generated fresh random salt!');
  });

  // -------------------------------------------------------------
  // TAB 3: Reuse & Breach Simulator Logic
  // -------------------------------------------------------------
  function renderAccountCards() {
    accountsGrid.innerHTML = simulationAccounts.map((acc, index) => {
      const isOrigin = acc.breachedFirst;
      return `
        <div class="account-sim-card" id="card-${acc.id}">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
            <div style="font-weight: 700; color: #fff; font-size: 1rem;">${acc.name}</div>
            <span class="step-badge" style="background: ${isOrigin ? 'rgba(244,63,94,0.2)' : 'rgba(99,102,241,0.2)'}; color: ${isOrigin ? '#fda4af' : '#a5b4fc'};">
              ${isOrigin ? 'Breach Origin' : 'Target Service'}
            </span>
          </div>
          <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            ${acc.category} • Security: <strong style="color: #cbd5e1;">${acc.securityLevel}</strong>
          </div>

          ${!isOrigin ? `
            <div class="toggle-switch-wrap">
              <span>Password Reused?</span>
              <label class="switch">
                <input type="checkbox" id="chk-reuse-${acc.id}" ${acc.reused ? 'checked' : ''} data-id="${acc.id}" data-prop="reused">
                <span class="slider"></span>
              </label>
            </div>
            <div class="toggle-switch-wrap">
              <span>Two-Factor Auth (2FA)?</span>
              <label class="switch">
                <input type="checkbox" id="chk-2fa-${acc.id}" ${acc.has2FA ? 'checked' : ''} data-id="${acc.id}" data-prop="has2FA">
                <span class="slider"></span>
              </label>
            </div>
          ` : `
            <div style="font-size: 0.82rem; color: #fda4af; padding: 0.4rem 0.6rem; background: rgba(244,63,94,0.1); border-radius: 0.5rem;">
              Vulnerable legacy software; attacker executes SQL injection dump.
            </div>
          `}
          <div id="status-tag-${acc.id}" style="margin-top: 0.75rem; font-size: 0.82rem; font-weight: 600; display: none;"></div>
        </div>
      `;
    }).join('');

    // Attach toggle listeners
    simulationAccounts.forEach(acc => {
      if (!acc.breachedFirst) {
        const chkReuse = document.getElementById(`chk-reuse-${acc.id}`);
        const chk2FA = document.getElementById(`chk-2fa-${acc.id}`);
        if (chkReuse) {
          chkReuse.addEventListener('change', (e) => {
            acc.reused = e.target.checked;
          });
        }
        if (chk2FA) {
          chk2FA.addEventListener('change', (e) => {
            acc.has2FA = e.target.checked;
          });
        }
      }
    });
  }

  btnStartSim.addEventListener('click', async () => {
    if (isSimulating) return;
    isSimulating = true;
    btnStartSim.disabled = true;
    btnStartSim.style.opacity = '0.6';
    simTimeline.innerHTML = '';

    // Reset card visuals
    simulationAccounts.forEach(acc => {
      const card = document.getElementById(`card-${acc.id}`);
      const tag = document.getElementById(`status-tag-${acc.id}`);
      if (card) {
        card.classList.remove('pwned', 'saved');
      }
      if (tag) {
        tag.style.display = 'none';
      }
    });

    await ReuseSimulator.runSimulation(simulationAccounts, (step) => {
      // Add event to timeline
      const evt = document.createElement('div');
      evt.className = 'timeline-event';
      const color = step.severity === 'danger' ? '#f43f5e' : (step.severity === 'success' ? '#10b981' : (step.severity === 'info' ? '#06b6d4' : '#f59e0b'));
      evt.style.borderLeftColor = color;
      evt.innerHTML = `
        <div style="font-size: 1.25rem;">
          ${step.severity === 'danger' ? '🚨' : (step.severity === 'success' ? '🛡️' : (step.severity === 'info' ? '📱' : '⚡'))}
        </div>
        <div>
          <div style="font-weight: 700; color: #fff; font-size: 0.92rem;">${step.title}</div>
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.2rem;">${step.detail}</div>
        </div>
      `;
      simTimeline.appendChild(evt);
      simTimeline.scrollTop = simTimeline.scrollHeight;

      // Update card visual
      if (step.siteId) {
        const card = document.getElementById(`card-${step.siteId}`);
        const tag = document.getElementById(`status-tag-${step.siteId}`);
        if (card && tag) {
          tag.style.display = 'block';
          if (step.status === 'compromised' || step.status === 'breached') {
            card.classList.add('pwned');
            tag.style.color = '#f43f5e';
            tag.textContent = '❌ ACCOUNT TAKEOVER';
          } else if (step.status === 'safe') {
            card.classList.add('saved');
            tag.style.color = '#10b981';
            tag.textContent = '✅ PROTECTED BY UNIQUE PASSWORD';
          } else if (step.status === 'defended') {
            card.classList.add('saved');
            tag.style.color = '#06b6d4';
            tag.textContent = '📱 DEFENDED BY 2FA';
          }
        }
      }
    });

    isSimulating = false;
    btnStartSim.disabled = false;
    btnStartSim.style.opacity = '1';
  });

  btnResetSim.addEventListener('click', () => {
    simulationAccounts = JSON.parse(JSON.stringify(ReuseSimulator.DEFAULT_ACCOUNTS));
    renderAccountCards();
    simTimeline.innerHTML = `
      <div style="color: var(--text-muted); font-size: 0.88rem; font-style: italic; padding: 0.5rem 0;">
        Simulation reset. Click "Simulate Forum Breach" above to start again.
      </div>
    `;
  });

  // k-Anonymity demo button
  btnDemoKanon.addEventListener('click', async () => {
    const testPwd = pwdInput.value || 'hunter2';
    const kanon = await ReuseSimulator.computeKAnonymitySteps(testPwd);
    kanonDemoOutput.style.display = 'block';
    kanonDemoOutput.innerHTML = `
      <div><strong>Original Password:</strong> "${escapeHtml(kanon.password)}"</div>
      <div><strong>Full SHA-1 Hash:</strong> ${kanon.fullHash}</div>
      <div style="margin-top: 0.5rem; color: #a5b4fc;">
        ➔ <strong>Prefix sent over the internet:</strong> <span style="background: rgba(99,102,241,0.3); padding: 2px 6px; border-radius: 4px; font-weight: bold; color: #fff;">${kanon.prefix}</span>
      </div>
      <div style="color: #6ee7b7;">
        ➔ <strong>Suffix kept strictly private in memory:</strong> <span style="background: rgba(16,185,129,0.2); padding: 2px 6px; border-radius: 4px; font-weight: bold; color: #fff;">${kanon.suffix}</span>
      </div>
      <div style="margin-top: 0.5rem; font-family: sans-serif; font-size: 0.82rem; color: #cbd5e1;">
        ${kanon.explanation}
      </div>
    `;
  });

  // -------------------------------------------------------------
  // TAB 4: Passphrase Generator Logic
  // -------------------------------------------------------------
  function updateGenerator() {
    const isPass = radioPassphrase.checked;
    const wordCount = parseInt(sliderWords.value, 10);
    labelWordCount.textContent = `${wordCount} words`;

    let generated = '';
    if (isPass) {
      document.getElementById('passphrase-settings').style.opacity = '1';
      document.getElementById('passphrase-settings').style.pointerEvents = 'auto';
      generated = Generator.generatePassphrase({
        wordCount: wordCount,
        separator: selectSeparator.value,
        capitalize: chkCapitalize.checked,
        addNumber: chkNumber.checked
      });
    } else {
      document.getElementById('passphrase-settings').style.opacity = '0.35';
      document.getElementById('passphrase-settings').style.pointerEvents = 'none';
      generated = Generator.generateRandomPassword(18, true);
    }

    genOutput.textContent = generated;

    // Calculate entropy for preview
    const patternResults = Patterns.analyze(generated);
    const entropy = EntropyCalc.calculateEntropy(generated, patternResults);
    const crackTimes = EntropyCalc.estimateCrackTimes(entropy.effectiveEntropy);

    genEntropyVal.textContent = `~${entropy.effectiveEntropy} bits`;
    genCrackVal.textContent = crackTimes.offlineFast.formatted;
  }

  radioPassphrase.addEventListener('change', updateGenerator);
  radioRandom.addEventListener('change', updateGenerator);
  sliderWords.addEventListener('input', updateGenerator);
  chkCapitalize.addEventListener('change', updateGenerator);
  chkNumber.addEventListener('change', updateGenerator);
  selectSeparator.addEventListener('change', updateGenerator);
  btnRegen.addEventListener('click', updateGenerator);

  btnCopyGen.addEventListener('click', () => {
    const text = genOutput.textContent.trim();
    if (text) {
      navigator.clipboard.writeText(text);
      showToast('Generated password copied to clipboard!');
    }
  });

  btnTestInInspector.addEventListener('click', () => {
    const text = genOutput.textContent.trim();
    if (!text) return;

    // Switch to inspector tab
    tabButtons[0].click();

    // Populate and evaluate
    pwdInput.value = text;
    evaluatePassword(text);
    showToast('Loaded into Vault Inspector!');
    pwdInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  // Initial runs
  updateCryptoLab();
  renderAccountCards();
  updateGenerator();

  // Load an initial demo password into inspector
  pwdInput.value = 'p@ssword123';
  evaluatePassword('p@ssword123');
});
