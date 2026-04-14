# SafeClick

AI-powered Chrome extension that detects phishing websites in real time.

## Quick start

### 1. Run the backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### 2. Configure the extension

Open `extension/config.js` and set your mode:

```js
// Switch to 'local' if you're running the backend on your own machine
const SAFECLICK_MODE = Mode.CLOUD;
const CLOUD_API_URL  = 'https://your-app.onrender.com';
```

### 3. Load the extension in Chrome

1. Go to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/` folder

## Modes

| Mode    | When to use                                      | How to set                         |
|---------|--------------------------------------------------|------------------------------------|
| `cloud` | Demo, production, sharing with others            | `SAFECLICK_MODE = Mode.CLOUD`      |
| `local` | Development or offline backup                    | `SAFECLICK_MODE = Mode.LOCAL`      |

## Deploying to the cloud (Render)

1. Push the `backend/` folder to a GitHub repository
2. Create a new **Web Service** on [render.com](https://render.com)
3. Set start command: `uvicorn main:app --host 0.0.0.0 --port 10000`
4. Copy the generated URL into `config.js` → `CLOUD_API_URL`

## Project structure

```
SafeClick/
├── extension/
│   ├── config.js          ← ✏️  Edit this to switch modes or set your cloud URL
│   ├── manifest.json      ← Extension metadata and permissions
│   ├── background.js      ← Service worker — manages the badge
│   ├── content.js         ← Injected into pages — DOM analysis + API call
│   ├── popup.html         ← Extension popup structure
│   ├── popup.js           ← Popup logic (dashboard, training, reports)
│   ├── popup.css          ← Popup styles
│   └── icons/             ← Extension icons
└── backend/
    ├── config.js          ← ✏️  Only file to edit for connection settings
    ├── main.py            ← FastAPI server — /analyze and /health endpoints
    ├── feature_extractor.py ← URL + HTML phishing feature extraction
    ├── model_trainer.py   ← ML model training script
    ├── phishing_model.pkl ← Pre-trained Random Forest model
    └── requirements.txt   ← Python dependencies
```

## Coding standards

- **JavaScript**: [Google JavaScript Style Guide](https://google.github.io/styleguide/jsguide.html)
- **Python**: [PEP 8](https://peps.python.org/pep-0008/) + [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
