# Phishing URL Checker (Flask website)

A small website that uses the trained Decision Tree (`model/phishing_url_model.pkl`) to judge a URL.
The user pastes a URL and gets a verdict (PHISHING / LEGITIMATE / SUSPICIOUS / UNCERTAIN), a phishing score and the red flags found.
The server never opens the URL: it only analyses the text.

## Project layout

```
phishing_web/
├── app.py                 Flask app: page + JSON API
├── url_analyzer.py        URL -> features -> model -> verdict (same code as the training notebook)
├── requirements.txt
├── model/
│   └── phishing_url_model.pkl   trained model (from the Colab notebook)
└── templates/
    └── index.html         the web page (HTML + CSS + JS in one file)
```

## Run locally

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

Use `scikit-learn==1.6.1` (pinned in `requirements.txt`). That is the version that trained the model; other versions load it with a warning and can give wrong results.

## Run in production

```bash
gunicorn -w 2 -b 0.0.0.0:8000 app:app
```

Put it behind HTTPS (nginx, Caddy, or a platform such as Render / Railway / Fly.io). On those platforms the start command is the `gunicorn` line above.

## API

```bash
curl -X POST http://127.0.0.1:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-verify-account.xyz/login"}'
```

Response:

```json
{
  "url": "http://paypal-verify-account.xyz/login",
  "judged_domain": "paypal-verify-account.xyz",
  "verdict": "PHISHING",
  "score": 0.8649,
  "serious_flags": [],
  "minor_flags": ["The domain name embeds the brand 'paypal' but ..."]
}
```

Invalid input returns HTTP 400 with `{"error": "..."}`.

## How the verdict is decided

| Verdict | When |
|---|---|
| PHISHING | phishing score >= 60% |
| UNCERTAIN | score between 40% and 60% |
| SUSPICIOUS | score <= 40% but a serious red flag is present (`@`, IP address, URL shortener, `xn--`, fake domain in the sub-domain) |
| LEGITIMATE | score <= 40% and no serious red flag |

Thresholds are `PHISH_THRESHOLD` and `LEGIT_THRESHOLD` in `url_analyzer.py`.

## Limits (please keep the disclaimer on the page)

- The model judges only the registered domain name (for example `paypal-verify-account` on `.xyz`). Scheme, `www`, sub-domain, path and query are ignored, because in the PhiUSIIL dataset every legitimate URL is a bare `https://www.` homepage, so those parts only teach a shortcut.
- On held-out domains: about 80% accuracy and about 60% recall. Roughly 4 in 10 phishing domains are missed.
- No page content, domain age, certificate or blocklist checks. "LEGITIMATE" is not a guarantee of safety.
- Only load `.pkl` files you created or trust: pickle files can run code when loaded.

## Retraining

If you retrain the model with different features, update `extract_features()` in `url_analyzer.py` to match, and replace `model/phishing_url_model.pkl`. The file must contain a dict with the keys `model`, `top_tlds` and `columns`, as saved by the notebook.
