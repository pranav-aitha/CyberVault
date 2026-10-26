# 🛡️ CyberVault — Interactive Password Security Playground & Cryptographic Inspector

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Vanilla JS](https://img.shields.io/badge/Vanilla-ES6%2B-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Web Crypto API](https://img.shields.io/badge/API-Web%20Crypto%20Subtle-green.svg)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Pure%20Client--Side)-brightgreen.svg)]()
[![Author](https://img.shields.io/badge/Author-Pranav%20Aitha-purple.svg)](https://github.com/pranav-aitha)

> **CyberVault** is a browser-native cybersecurity playground and password strength diagnostic inspector. Built with modern glassmorphism aesthetics and native HTML5/ES6+/Web Crypto standards, it empowers users to inspect entropy, uncover predictable behavioral patterns, understand password hashing/salting/peppering, and visualize the ripple effect of credential reuse across data breaches.

🌐 **Live GitHub Pages Demo**: [https://pranav-aitha.github.io/CyberVault/](https://pranav-aitha.github.io/CyberVault/)

---

## 📑 Table of Contents
1. [Why CyberVault?](#-why-cybervault)
2. [Core Modules & Features](#-core-modules--features)
   - [1. Vault Inspector](#1-vault-inspector)
   - [2. Cryptography Lab](#2-cryptography-lab)
   - [3. Password Reuse & Breach Simulator](#3-password-reuse--breach-simulator)
   - [4. Diceware Passphrase Generator](#4-diceware-passphrase-generator)
3. [Mathematical & Cryptographic Foundations](#-mathematical--cryptographic-foundations)
   - [Shannon Entropy Calculation](#shannon-entropy-calculation)
   - [Threat Vector Cracking Models](#threat-vector-cracking-models)
   - [The Mathematics of Passphrases vs. Cryptic Symbols](#the-mathematics-of-passphrases-vs-cryptic-symbols)
   - [k-Anonymity Explained](#k-anonymity-explained)
4. [Project Structure](#-project-structure)
5. [How to Run Locally](#-how-to-run-locally)
6. [Deployment to GitHub Pages](#-deployment-to-github-pages)
7. [Author & Socials](#-author--socials)
8. [License](#-license)

---

## 💡 Why CyberVault?

Traditional password meters are notoriously flawed. Most simply check for character diversity (e.g., *"Does it have an uppercase letter, a number, and a symbol?"*). This misleads users into thinking passwords like `P@ssw0rd123!` or `Autumn2024!` are secure, when in fact automated cracking rigs (like **Hashcat** with dictionary rules) tear through them in **less than 20 milliseconds**.

CyberVault dismantles these myths by:
- Inspecting **true information-theoretic entropy** instead of counting character classes.
- Detecting human typing patterns: **keyboard walks, leetspeak, sequential digits, birth years, and dictionary stems**.
- Showing **why 4 random words (passphrase)** defeat an 8-character symbol salad every single time.
- Providing an **interactive cryptographic sandbox** explaining why hashing alone isn't enough and how salting and peppering safeguard billions of web users.
- Demonstrating the catastrophic **ripple effect of password reuse** across breached services.

---

## 🚀 Core Modules & Features

### 1. Vault Inspector
- **Dynamic 5-Segment Glowing Meter**:
  - `Very Weak` (0–27 bits) — Red
  - `Weak / Moderate` (28–45 bits) — Amber
  - `Good / Decent` (46–64 bits) — Sky Blue
  - `Strong` (65–84 bits) — Emerald Green
  - `Ultra Fortress` (85+ bits) — Violet/Rainbow Glow
- **Live Heuristics & Vulnerability Radar**:
  - **Keyboard Walks**: Detects horizontal row walks (`qwerty`, `poiuy`, `zxcvbn`), vertical columns (`1qaz`, `2wsx`, `0p;/`), and numpad runs.
  - **Dictionary Stems & Top Breaches**: Identifies words from top breach dictionaries (`password`, `dragon`, `welcome`, `iloveyou`).
  - **Leetspeak Normalizer**: Reverse-engineers substitutions (`@` $\to$ `a`, `3` $\to$ `e`, `$` $\to$ `s`, `0` $\to$ `o`, `!` $\to$ `i`).
  - **Repetition & Sequence Analysis**: Flags repeated chunks (`abcabc`, `passpass`) and sequential character runs (`12345`, `fedcba`).
  - **Date Patterns**: Flags birth years (`1950`–`2026`) and common calendar arrangements.
- **Passphrase Intelligence**: Automatically recognizes multi-word Diceware structures, applying informational entropy calculations.
- **Micro-Animations**:
  - CSS shake effect on critical weakness detection.
  - Canvas confetti particle engine upon hitting `Strong` or `Ultra Fortress`.
  - Live show/hide visibility toggle and clipboard copy with animated toast alerts.

---

### 2. Cryptography Lab
An interactive educational laboratory powered by the browser's native **Web Crypto API** (`crypto.subtle`):
- **Stage 1: One-Way Hashing (SHA-256)**:
  - Generates real-time 256-bit hexadecimal digests.
  - Explains the deterministic nature of hashes and why precomputed **Rainbow Tables** render raw hashes vulnerable.
- **Stage 2: Salting (Salt + Password)**:
  - Generates 128-bit cryptographically secure random salts via `crypto.getRandomValues`.
  - **Alice vs. Bob Twin Experiment**: Shows that when two users pick identical passwords (`hunter2`), their salted hashes are 100% unique, permanently neutralizing precomputed rainbow tables.
- **Stage 3: Peppering (Password + Salt + Pepper)**:
  - Simulates a secret server-side key stored in an HSM or KMS (never in the SQL database).
  - Demonstrates defense-in-depth: Even if a database leaks via SQL injection, offline brute-forcing remains impossible without the hardware key.
- **Stage 4: Key Stretching & Memory-Hard Hashing**:
  - Explains why SHA-256 is designed to be fast (checking file integrity), while password algorithms (**Argon2id, bcrypt, PBKDF2**) are intentionally slow and memory-intensive to stop GPU clusters.

---

### 3. Password Reuse & Breach Simulator
- **Credential Stuffing Simulation**:
  - An interactive scenario modeling an initial SQL injection dump on an *Indie Gaming Forum*.
  - An automated botnet launches credential stuffing attacks against linked accounts (*MegaShop Retail*, *Primary Email*, and *Banking Portal*).
  - Demonstrates why reusing a password on even a single low-security community site compromises high-value financial and personal portals.
  - Interactive switches let users configure **Password Reuse** and **Two-Factor Authentication (2FA)** to observe how 2FA blocks attackers even when passwords leak.
- **k-Anonymity Interactive Demo**:
  - Step-by-step interactive breakdown of the mathematical privacy technique used by *HaveIBeenPwned*.
  - Splits a SHA-1 hash into a 5-character public prefix and a 35-character private suffix, proving that zero-knowledge breach lookups keep user passwords secret.

---

### 4. Diceware Passphrase Generator
- **XKCD 936 Principles**: Generates easy-to-remember, cryptographically massive passphrases (e.g., `velvet-granite-nebula-falcon-42`).
- **Configurable Settings**:
  - Word length slider (3 to 6 words).
  - Separators: Hyphens (`-`), Spaces (` `), Dots (`.`), or Underscores (`_`).
  - Word capitalization toggle & numeric affix toggle.
  - High-entropy random character mode (18+ characters).
- **One-Click Testing**: Instant "Test in Inspector" button transfers generated passwords directly into the live diagnostic suite.

---

## 🧮 Mathematical & Cryptographic Foundations

### Shannon Entropy Calculation
Entropy represents the number of guesses an attacker must make to crack a secret:

$$H = L \times \log_2(R)$$

Where:
- $L$ is the password length.
- $R$ is the size of the character pool:
  - Lowercase (`a-z`): 26
  - Uppercase (`A-Z`): 26
  - Numbers (`0-9`): 10
  - Symbols: 33
  - Full ASCII Pool: $26 + 26 + 10 + 33 = 95$

CyberVault computes **Effective Entropy** by deducting penalties for predictable patterns, repeated chunks, and common dictionary roots:

$$H_{\text{effective}} = \max\left(0, H - P_{\text{patterns}}\right)$$

### Threat Vector Cracking Models
Cracking times are calculated assuming an attacker on average must search $50\%$ of the keyspace ($2^{H - 1}$ guesses):

| Threat Model | Hardware / Environment | Guesses per Second | Description |
| :--- | :--- | :--- | :--- |
| **Online Throttled** | Web portal with CAPTCHA & lockout | ~0.027 / sec (100 / hr) | Protected login APIs |
| **Online Fast** | Unthrottled web API & botnets | 1,000 / sec | Poorly secured endpoints |
| **Offline Slow Hash** | Salted Argon2id / bcrypt on GPUs | 100,000 / sec | State-of-the-art storage |
| **Offline Fast Hash** | 8x NVIDIA RTX 4090 GPU Cluster | 100,000,000,000 / sec ($10^{11}$) | Raw MD5 / SHA-256 / NTLM |

### The Mathematics of Passphrases vs. Cryptic Symbols
- **Cryptic short password** (`Tr0ub4dor&3`, 11 chars):
  - Hard for humans to remember.
  - Easy for machines to crack with leetspeak dictionary rules ($\approx 28$ bits).
- **Random 4-word passphrase** (`correct-horse-battery-staple`, 28 chars):
  - Chosen from a Diceware pool of 7,776 words.
  - Entropy $= 4 \times \log_2(7776) \approx 51.7$ bits.
  - Effortless to remember, yet requires **over 3,400 years** to crack on dedicated GPU rigs!

---

## 📁 Project Structure

```
CyberVault/
├── index.html              # Modern semantic HTML5 markup & responsive UI
├── styles.css              # Glassmorphic CSS3 styling, neon glows & keyframes
├── LICENSE                 # MIT Open Source License
├── README.md               # Comprehensive documentation & guides
├── .gitignore              # Git ignore rules for clean repository
├── start.bat               # Windows instant launcher shortcut
└── js/
    ├── app.js              # Application coordinator & event bindings
    ├── patterns.js         # Heuristic pattern detection (walks, leet, dictionaries)
    ├── entropy.js          # Shannon entropy calculator & threat crack times
    ├── crypto-lab.js       # Web Crypto API hashing, salting & peppering pipeline
    ├── reuse-simulator.js  # Credential stuffing ripple simulator & k-Anonymity
    ├── generator.js        # Diceware passphrase & secure password generator
    └── confetti.js         # Canvas particle animation engine
```

---

## 💻 How to Run Locally

Because CyberVault is built with pure web standards and zero build dependencies, you can run it in seconds:

### Option 1: Direct Browser Launch
Simply double-click [`start.bat`](start.bat) or open [`index.html`](index.html) in any modern browser (Chrome, Edge, Firefox, Safari, Brave).

### Option 2: Lightweight Static Server
```bash
# Using Python 3
python -m http.server 8000

# Using Node.js npx
npx serve .
```
Navigate to `http://localhost:8000` in your browser.

---

## 🌐 Deployment to GitHub Pages

To deploy your own copy on GitHub Pages:
1. Fork or push this repository to GitHub.
2. In your repository, go to **Settings** $\to$ **Pages**.
3. Under **Branch**, select `main` (or `master`) and folder `/ (root)`.
4. Click **Save**. Within 1–2 minutes, your live site will be accessible at:
   `https://<your-username>.github.io/<repo-name>/`

---

## 👨‍💻 Author & Socials

Created with ❤️ by **Pranav Aitha**

- 📸 **Instagram**: [@pranav_aitha](https://instagram.com/pranav_aitha)
- 🐙 **GitHub**: [@pranav-aitha](https://github.com/pranav-aitha)
- 🐦 **X (Twitter)**: [@PRANAV_AITHA](https://x.com/PRANAV_AITHA)

Feel free to connect, star the repository, or submit issues and pull requests!

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
Copyright (c) 2026 Pranav Aitha
```
