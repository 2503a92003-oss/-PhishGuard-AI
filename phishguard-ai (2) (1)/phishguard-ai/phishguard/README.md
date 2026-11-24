# PhishGuard AI

Paste a suspicious message or link, or upload an `.eml` email file, and get a Low, Medium or High risk rating with the specific warning signs highlighted. Scans are saved, can be grouped into investigations, and exported as reports.

## Run it

Create and activate a virtual environment:

**Windows PowerShell**

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```


Then install dependencies and run the app:

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Run the detector tests with `python -m unittest`.

Optional: set `PHISHGUARD_SECRET` to keep sessions valid across restarts, and `PHISHGUARD_DB` to move the database.

## How it works

| File | Role |
|---|---|
| `detector.py` | Rule engine (wording rules + link checks) and optional model hook |
| `app.py` | Flask routes, SQLite storage, CSRF and security headers |
| `templates/`, `static/` | Jinja pages, CSS, small JS file |
| `train_model.py` | Trains the optional TF-IDF + logistic regression model |
| `test_detector.py` | Unit tests for the rules |

**Scoring.** Each rule adds points (for example link imitates a brand +30, IP-address link +25, asks for a password +20). The total is capped at 100: under 25 is Low, under 45 Medium, otherwise High.

**Machine learning (optional).** Run `python train_model.py --csv your_data.csv` (columns `text,label`, 1 = phishing). This writes `model.joblib`, and the app picks it up on restart. The model can only raise a score, never lower it. The built-in sample has 28 messages and is for demonstration only; use a real corpus before relying on it.

## Safety choices

- Links are never opened, fetched or resolved, so scanning live phishing is safe.
- Links are shown defanged (`hxxp://evil[.]example`) on results and reports.
- CSRF tokens on every POST, parameterised SQL, auto-escaped templates, a strict Content-Security-Policy, and CSV export that neutralises spreadsheet formulas.

## Limits and next steps

Rules are heuristics, so expect false positives and misses; a Low score is not a guarantee. Ideas: add user accounts, `.eml` header parsing (SPF/DKIM/Reply-To), threat-feed lookups, a JSON API with token auth, and a larger trained model.
