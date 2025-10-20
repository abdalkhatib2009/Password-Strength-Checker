# Password Strength Checker — Enhanced (Local Demo)

**Password Strength Checker** is a single-file Flask web application that evaluates password strength using multiple signals and checks whether a password appears in a local wordlist (e.g. `rockyou.txt`) or an uploaded wordlist.
**Intended use:** local, educational, classroom demos, and student exercises.
**Do not** deploy this publicly or use real production accounts/passwords with this app.

---

## Features

* Masked password input (`<input type="password">`).
* Multi-signal scoring (length, character-class diversity, entropy estimate, repeats, sequences).
* Prioritized, actionable recommendations.
* Local breach checks:

  * Exact-match check against system wordlists (e.g. `/usr/share/wordlists/rockyou.txt`) if present.
  * Upload your own wordlist (one password per line) for checks (limited-size load to avoid OOM).
  * Falls back to a small built-in common-password list for quick demos.
* Clean, responsive single-page UI with result panel and footer credit.
* Fully local — passwords never leave the machine (no external API calls).

---

## Quick start

1. Clone or copy the repository into a local folder.
2. Make sure you have Python 3.8+ installed.

Install dependencies:

```bash
pip install flask
```

(Optionally install `bcrypt` if you plan to integrate bcrypt hashing elsewhere, but not required for this app.)

3. Save the app file as `pw_strength_checker.py` (or use the filename provided).
4. (Optional) Place a large wordlist such as `rockyou.txt` in one of the expected locations (recommended if you want faster breach checks):

```
/usr/share/wordlists/rockyou.txt
/path/to/project/rockyou.txt
/path/to/project/wordlist.txt
```

5. Run the app:

```bash
python pw_strength_checker.py
```

6. Open a browser and visit: `http://127.0.0.1:5100`

---

## How it works (brief)

* **Scoring:** the app estimates entropy (bits) from character classes and length, applies bonuses for diversity and penalties for weak patterns (sequences, repeats, common-list membership). The final score is normalized to `0–100`.
* **Breach check:** exact-match only. If a large wordlist exists on disk the app will stream it and compare lowercased lines against the candidate password. If you upload a wordlist, the app will load up to a configurable limit (default 500k lines) into memory and check exact matches.
* **Privacy:** everything runs locally. The app does not transmit passwords to remote services. Do not enable any remote integrations unless you fully understand privacy implications.

---

## Configuration & Options

* `COMMON_WORDLIST_PATHS` — defined in the Python file; edit to add additional default locations to look for `rockyou.txt`.
* Upload limit & load limit — the app limits loaded lines for uploaded wordlists to avoid out-of-memory situations. Adjust in the source (`stream_wordlist_to_set` limit).
* `app.secret_key` — the demo sets a development-only secret; do not use this in production.

---

## Safety & Usage Guidelines (READ THIS)

* This tool is strictly for **local educational use**. Do not deploy on the public internet.
* **Never** use real user passwords or production secrets for testing here.
* The app writes temporary files (uploaded wordlists, small demo wordlist) into the working directory. Remove them after demos if they contain sensitive material.
* The breach-check is an **exact match** against wordlists. It does **not** detect creative variants or use k-anonymity APIs.

---

## Suggested classroom activities

* Demonstrate how short/common passwords score poorly vs passphrases.
* Have students create passphrases and iterate to improve score and recommendations.
* Upload a curated subset of `rockyou` (e.g., 2k–10k entries) to show quick breach detection without long processing times.
* Compare results to `zxcvbn` or other libraries (exercise: integrate zxcvbn and compare scores).

---

## File outputs & artifacts

Running the app may create:

* uploaded wordlist files (if you upload via the UI),
* `demo_wordlist.txt` (fallback small list, if needed).
  Remove these files after use if they contain any sensitive data.

---

## Extending the project

Ideas you might add:

* Add optional integration with Dropbox or local S3 for storing uploaded wordlists (local-only).
* Add a manual/async breach-check route that streams a very large wordlist and reports progress.
* Add unit tests (pytest) for scoring heuristics and pattern detection.
* Add a Dockerfile for an isolated demo environment.

---

## License & Credits

* **Author / Dev:** Eng CyberWolf

This repository is released under the **MIT License** (choose a license file when publishing to GitHub). Use responsibly and only for legitimate educational purposes.

