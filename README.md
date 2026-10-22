# 🛡️ LoginGuard — Intelligent Fake Login Website Detection System

LoginGuard checks a website address for phishing warning signs **without opening the site**.
It uses simple, explainable rules plus an optional Google Safe Browsing lookup.
It does **not** use AI or machine learning.

## How the files work together
| File | Job |
|---|---|
| `app.py` | The Streamlit web page. Takes the URL, shows results. |
| `url_analyzer.py` | Checks the URL text with rules and gives a score. |
| `threat_checker.py` | Asks Google Safe Browsing if the URL is a known threat. |
| `assessment.py` | Combines both into Green / Orange / Red / Unable to determine. |
| `tests/` | Automatic tests (no real phishing sites needed). |

Flow: `app.py` → `url_analyzer` → `threat_checker` → `assessment` → shown on screen.

## Run locally
1. Install Python 3.10+ from python.org.
2. Open a terminal in this folder and run:
   ```
   python -m venv venv
   venv\Scripts\activate        (Windows)   or   source venv/bin/activate   (Mac/Linux)
   pip install -r requirements-dev.txt
   streamlit run app.py
   ```
3. Your browser opens at http://localhost:8501.

## Optional: turn on the threat-database check
1. Go to Google Cloud Console, create a project, enable **Safe Browsing API**, and create an API key (free for non-commercial use; check Google's current terms).
2. Locally: copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and paste your key. This file is git-ignored.
3. Without a key, the app still works and clearly says only local analysis was done.

## Test
```
pytest
```
Try these in the app too:
- `https://www.example.com` → Green
- `http://192.168.1.5/secure-login` → Red (local rules only)
- `https://paypal.com@evil.example.net` → warning for the '@' trick
- `not a url` → Unable to determine
- `https://phish-demo.test` → **SIMULATED** known-threat result (a fake fixture, not real intelligence)
- `https://clean-demo.test` → simulated non-match

Redirects: LoginGuard never follows links, so it only flags link shorteners and cannot say where they lead.

## Upload to GitHub
1. Create a free account and a new empty repository (e.g. `loginguard`) on github.com.
2. In this folder:
   ```
   git init
   git add .
   git commit -m "LoginGuard first version"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/loginguard.git
   git push -u origin main
   ```
3. Check that `secrets.toml` is NOT in the repository.

## Deploy on Streamlit Community Cloud
1. Go to share.streamlit.io and sign in with GitHub.
2. Click **Create app**, choose your repository, branch `main`, main file `app.py`.
3. Open **Advanced settings → Secrets** and paste:
   `GOOGLE_SAFE_BROWSING_API_KEY = "your-key-here"`
4. Click **Deploy**. You get a link like `https://your-app.streamlit.app` that works on phones and laptops.

## Limitations
- Rules are simple and can miss attacks or flag real sites (for example, a brand name inside a real but different domain).
- A Green result is **not** a safety guarantee. A database "no match" does not prove safety either.
- Brand-new phishing sites are often not in any database yet.
- Redirects and page content are never inspected.
