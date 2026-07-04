# PhishGuard-AI Complete

Enterprise-grade, real-time Anti-Phishing Browser Security Suite. Performs semantic NLP analysis and mule-account scanning on raw DOM payloads.

## Running Locally

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the backend server:
   ```bash
   uvicorn main:app --reload
   ```

3. Load the Chrome Extension:
   - Go to `chrome://extensions/`
   - Enable **Developer Mode**
   - Click **Load unpacked** and select the `chrome_extension` folder.
