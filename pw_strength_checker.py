#!/usr/bin/env python3
"""
Enhanced Password Strength Checker (Flask)

- Runs on 127.0.0.1:5100 by default
- Masks password input in the form
- Multi-signal scoring (length, classes, entropy, repeats, sequences)
- Prioritized recommendations
- Local breach check against system wordlist or uploaded wordlist
- Robust error logging: exceptions write to error.log

SECURITY: This is a local demo only. Do NOT deploy publicly. If a password is
found in a wordlist, the app will display it in clear text on the results page
(per your request). Use only test passwords.
"""
from flask import Flask, request, render_template_string
import math
import os
import re
import time
import traceback

app = Flask(__name__)
app.secret_key = "dev-only-secret"

APP_DIR = os.getcwd()
COMMON_WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/dict/rockyou.txt",
    os.path.join(APP_DIR, "rockyou.txt"),
    os.path.join(APP_DIR, "wordlist.txt"),
]

BUILTIN_COMMON = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "123123", "letmein", "welcome", "admin", "passw0rd",
    "iloveyou", "monkey", "dragon"
}

SEQUENCE_PATTERNS = [
    "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"
]

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Password Strength Checker — Enhanced</title>
  <style>
    body { font-family: Inter, Arial, sans-serif; background:#f4f6f8; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0}
    .card { width:880px; max-width:96%; background:white; padding:22px; border-radius:10px; box-shadow:0 12px 30px rgba(0,0,0,0.08) }
    h1 { margin:0 0 8px 0 }
    form { display:flex; gap:12px; align-items:flex-start; }
    .col { flex:1 }
    label { display:block; margin-bottom:6px; color:#333 }
    input[type=text], input[type=password], select { width:100%; padding:10px; border-radius:8px; border:1px solid #e2e6ea; box-sizing:border-box }
    button { padding:10px 14px; border-radius:8px; background:#0b66ff; color:white; border:none; cursor:pointer }
    .muted { color:#666; font-size:0.95rem }
    .result { margin-top:16px; padding:12px; border-radius:8px; background:#fafbff; border:1px solid #eef2ff }
    .meter { height:14px; background:#eee; border-radius:7px; overflow:hidden; margin-top:8px }
    .meter > span { display:block; height:100% }
    pre { background:#f8f9fb; padding:8px; border-radius:6px; overflow:auto }
    ul { margin:6px 0 6px 18px }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:0.8rem; color:white }
    .ok { background:#28a745 }
    .warn { background:#ffc107; color:#222 }
    .bad { background:#dc3545 }
    footer { margin-top:14px; text-align:center; color:#777; font-size:0.85rem }
    .small { font-size:0.9rem; color:#444 }
    .grid { display:grid; grid-template-columns: 1fr 260px; gap:12px }
    .right-card { background:#fff; border-radius:8px; padding:12px; border:1px solid #eef2f8 }
    .error { background:#fff3f3; border:1px solid #f5c2c2; color:#7a1a1a; padding:8px; border-radius:6px; margin-bottom:12px }
  </style>
</head>
<body>
  <div class="card">
    <h1>Password Strength Checker — Enhanced</h1>
    <div class="muted">Local demo — passwords never leave this machine unless you upload a wordlist.</div>

    {% if error_message %}
      <div class="error"><strong>Note:</strong> {{ error_message }} — see <code>error.log</code> for details.</div>
    {% endif %}

    <hr style="margin:12px 0">
    <form method="post" enctype="multipart/form-data">
      <div class="col">
        <label>Optional username (for context):</label>
        <input type="text" name="username" placeholder="e.g., alice">

        <label style="margin-top:10px">Password (input is masked):</label>
        <input type="password" name="password" required autocomplete="new-password" placeholder="Type a password">

        <label style="margin-top:10px">Check breach against:</label>
        <select name="wordlist_choice">
          <option value="">(auto) system rockyou / builtin</option>
          <option value="upload">Upload a wordlist file (one password per line)</option>
        </select>

        <div style="margin-top:8px">
          <input type="file" name="wordlist_file">
          <div class="muted small">If you upload, it will be used for breach checks only and saved in the app folder.</div>
        </div>

        <div style="margin-top:12px; display:flex; gap:8px">
          <button type="submit">Check password</button>
          <a href="{{ url_for('index') }}"><button type="button" style="background:#6c757d">Reset</button></a>
        </div>
      </div>
      <div style="width:320px">
        <div class="right-card">
          <div class="small"><strong>How scoring works</strong></div>
          <ul>
            <li>Length & character-class diversity matter most.</li>
            <li>Entropy estimate approximates brute-force hardness.</li>
            <li>Dictionary/wordlist matches are treated as breaches.</li>
            <li>Recommendations are prioritized and actionable.</li>
          </ul>
        </div>
      </div>
    </form>

    {% if result %}
      <div class="result">
        <div style="display:flex; justify-content:space-between; align-items:center">
          <div>
            <strong>Score:</strong> {{ result.score }} / 100
            <div class="meter" aria-hidden="true">
              <span style="width:{{ result.score }}%; background:{{ result.color }}"></span>
            </div>
            <div class="muted small">Entropy estimate: {{ result.entropy|round(1) }} bits — Estimated guesses: {{ result.guess_count_str }}</div>
          </div>
          <div style="text-align:right">
            {% if result.breached %}
              <div class="badge bad">BREACHED</div>
            {% else %}
              <div class="badge ok">Not found in selected wordlist</div>
            {% endif %}
            <div class="muted small" style="margin-top:6px">Checked against: {{ result.checked_source }}</div>
          </div>
        </div>

        <hr>
        <div style="display:flex; gap:12px">
          <div style="flex:1">
            <strong>Checks</strong>
            <ul>
              <li>Length: {{ result.length }} chars</li>
              <li>Classes: {{ result.class_count }} (lower:{{ 'Y' if result.has_lower else 'N' }}, upper:{{ 'Y' if result.has_upper else 'N' }}, digits:{{ 'Y' if result.has_digit else 'N' }}, symbols:{{ 'Y' if result.has_symbol else 'N' }})</li>
              <li>Contains dictionary word: {{ 'Yes' if result.is_common else 'No' }}</li>
              <li>Has long repeated sequence: {{ 'Yes' if result.has_repeat else 'No' }}</li>
              <li>Has keyboard/sequence patterns: {{ 'Yes' if result.has_sequence else 'No' }}</li>
            </ul>
          </div>
          <div style="width:320px">
            <strong>Top recommendations</strong>
            <ol>
              {% for r in result.recommendations %}
                <li>{{ r }}</li>
              {% endfor %}
            </ol>
          </div>
        </div>

        {% if result.breached %}
          <hr>
          <strong>Breach details</strong>
          <pre>Password found: "{{ result.plain_password }}" — Source: {{ result.checked_source }}</pre>
          <div class="muted small">The password is displayed above exactly as you entered it. Remove sensitive examples immediately after demo.</div>
        {% elif result.breach_details %}
          <hr>
          <strong>Breach details</strong>
          <pre>{{ result.breach_details }}</pre>
        {% endif %}
      </div>
    {% endif %}

    <footer> Developed by Eng CyberWolf </footer>
  </div>
</body>
</html>
"""

# ---------------- helper functions ---------------- #

def estimate_entropy(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)

def human_readable_guess_count(guesses: float) -> str:
    if guesses < 1e3:
        return f"{int(guesses)} guesses"
    for unit, div in (("k", 1e3), ("M", 1e6), ("B", 1e9), ("T", 1e12), ("P", 1e15)):
        if guesses < div * 1000:
            return f"{guesses/div:.2f}{unit} guesses"
    return f"{guesses:.2e} guesses"

def has_sequence(password: str, min_len: int = 4) -> bool:
    pw = password.lower()
    for seq in SEQUENCE_PATTERNS:
        for i in range(len(seq) - min_len + 1):
            slice_ = seq[i:i+min_len]
            if slice_ in pw or slice_[::-1] in pw:
                return True
    # Check for repeated digits 4+ times (fixed regex uses a capturing group)
    if re.search(r"(\d)\1{3,}", pw):
        return True
    return False

def has_repeated_run(password: str, min_len: int = 4) -> bool:
    if re.search(r"(.)\1{" + str(min_len-1) + r",}", password):
        return True
    n = len(password)
    for size in (2, 3, 4):
        if n >= size * 3:
            pattern = password[:size]
            if pattern * (n // size) == password[:size*(n//size)]:
                return True
    return False

def is_common_password(password: str, loaded_set=None) -> (bool, str):
    pw_lower = password.strip().lower()
    if loaded_set:
        if pw_lower in loaded_set:
            return True, f"uploaded wordlist"
        return False, "uploaded wordlist"
    if pw_lower in BUILTIN_COMMON:
        return True, "builtin common list"
    for path in COMMON_WORDLIST_PATHS:
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if pw_lower == line.strip().lower():
                            return True, f"system wordlist: {path}"
        except Exception:
            continue
    return False, "none"

def compute_score(password: str, loaded_set=None) -> dict:
    length = len(password)
    entropy = estimate_entropy(password)
    guesses = max(1.0, 2 ** entropy)

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    class_count = sum([has_lower, has_upper, has_digit, has_symbol])

    seq = has_sequence(password)
    rep = has_repeated_run(password)
    common, source = is_common_password(password, loaded_set)

    # Score logic: combine entropy portion + class bonus, apply penalties
    entropy_score = min(80, entropy)  # map entropy to 0-80
    class_bonus = (class_count - 1) * 6
    if length >= 16:
        class_bonus += 6

    penalty = 0
    if common:
        penalty += 60
    if seq:
        penalty += 12
    if rep:
        penalty += 12
    if length < 8:
        penalty += 12
    if length < 6:
        penalty += 20

    raw_score = entropy_score + class_bonus - penalty
    score = max(0, min(100, int(raw_score)))
    color = "#dc3545" if score < 40 else ("#ffc107" if score < 70 else "#28a745")

    recs = []
    if common:
        recs.append("This password appears in a common password list — do not use it.")
    if length < 12:
        recs.append("Use a passphrase of at least 12 characters (longer is better).")
    if not has_symbol:
        recs.append("Add symbols/special characters (e.g., !@#$%).")
    if not has_upper:
        recs.append("Add some uppercase letters.")
    if not has_digit:
        recs.append("Include digits (0-9).")
    if seq:
        recs.append("Avoid obvious sequences like '1234' or 'qwerty'.")
    if rep:
        recs.append("Avoid long repeated characters or repeated short patterns.")
    if not recs:
        recs.append("Good password. Consider using a password manager to generate & store unique passwords.")

    return {
        "score": score,
        "entropy": entropy,
        "guess_count_str": human_readable_guess_count(guesses),
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "class_count": class_count,
        "has_sequence": seq,
        "has_repeat": rep,
        "is_common": common,
        "breached": common,
        "checked_source": source,
        "recommendations": recs,
        "color": color,
        "plain_password": password if common else "",
        "breach_details": f"Password found in {source}" if common else ""
    }

def stream_wordlist_to_set(uploaded_file_path: str, limit: int = 500000) -> set:
    s = set()
    try:
        with open(uploaded_file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= limit:
                    break
                word = line.strip().lower()
                if word:
                    s.add(word)
    except Exception:
        pass
    return s

def secure_filename(filename: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(filename))

# ---------------- Flask route ---------------- #

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error_message = None
    try:
        if request.method == "POST":
            password = request.form.get("password", "")
            choice = request.form.get("wordlist_choice", "")
            uploaded = request.files.get("wordlist_file")

            loaded_set = None
            checked_source = "builtin"
            if choice == "upload" and uploaded and getattr(uploaded, "filename", ""):
                filename = secure_filename(uploaded.filename)
                save_path = os.path.join(APP_DIR, filename)
                try:
                    uploaded.save(save_path)
                    loaded_set = stream_wordlist_to_set(save_path, limit=500000)
                    checked_source = f"uploaded: {filename} (limited load)"
                except Exception:
                    loaded_set = None
                    checked_source = "uploaded (failed to read)"

            # check breach first: loaded_set -> builtin -> system
            breached = False
            breach_source = "none"
            if loaded_set is not None:
                if password.strip().lower() in loaded_set:
                    breached = True
                    breach_source = checked_source
            else:
                found, source = is_common_password(password, None)
                if found:
                    breached = True
                    breach_source = source

            # compute score
            result = compute_score(password, loaded_set if loaded_set else None)
            # override checked_source and breached state
            result["checked_source"] = breach_source if breached else result["checked_source"]
            result["breached"] = breached
            if breached:
                # per user request: show cleartext password in the UI if breached (local demo only)
                result["plain_password"] = password
                result["breach_details"] = f"Password found in {breach_source}"
    except Exception:
        tb = traceback.format_exc()
        try:
            with open(os.path.join(APP_DIR, "error.log"), "a", encoding="utf-8") as fh:
                fh.write(f"\n\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                fh.write(tb)
        except Exception:
            pass
        error_message = "An internal error occurred. Details written to error.log."

    return render_template_string(TEMPLATE, result=result, error_message=error_message)

if __name__ == "__main__":
    print("Starting Password Strength Checker (local demo) on http://127.0.0.1:5100")
    app.run(host="127.0.0.1", port=5100, debug=False)
