# PhishCreator Pro - Complete Edition


## Features

### Core Capabilities

✅ **Live Traffic Analysis**: Capture authentication flows using Playwright browser automation  
✅ **Intelligent Auth Flow Classification**: Automatically detect form-based, API-driven, OAuth, SAML, and multi-step authentication  
✅ **Dynamic Credential Extraction**: Find credentials in forms, JSON payloads, and complex API formats without manual regex  
✅ **Smart Cookie Analysis**: Prioritize authentication cookies using pattern matching and attribute scoring  
✅ **Adaptive Sub-Filter Generation**: Create URL rewriting rules and anti-detection bypasses  
✅ **Self-Improvement Engine**: Learn from successes and failures to improve future generations  
✅ **AI-Powered Refinement**: Integrate with Manus AI for advanced phishlet optimization  

### Module Architecture

```
phishcreator_complete/
├── app_enhanced.py                      # Main Flask application
├── requirements.txt                      # Python dependencies
├── modules/
│   ├── live_traffic_analyzer.py         # Playwright-based traffic capture
│   ├── phishlet_parser.py               # YAML parsing and validation
│   ├── har_comparator.py                # HAR vs phishlet comparison
│   ├── phishlet_updater.py              # Automatic phishlet fixing
│   ├── auth_flow_classifier.py          # Authentication type detection
│   ├── intelligent_credential_extractor.py  # Dynamic credential extraction
│   ├── smart_cookie_analyzer.py         # Cookie prioritization
│   ├── dynamic_phishlet_generator.py    # Complete phishlet synthesis
│   ├── self_improvement_engine.py       # Learning database
│   └── ai_phishlet_refiner.py           # Manus AI integration
└── README.md                             # This file
```

## Installation

### 0. Use the correct Python (required for Playwright)

Playwright does **not** install cleanly on Python 3.13 on macOS (greenlet build issues).
This repo includes a ready-to-use Python 3.12 virtualenv:

```bash
source phishcreator/.venv312/bin/activate
python --version  # should show 3.12.x
```

If you use VS Code, open the Command Palette → **Python: Select Interpreter** →
choose:

`phishcreator/.venv312/bin/python`

(Also, this repo ships `.vscode/settings.json` to point Pylance at that interpreter.)

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Playwright Browsers

```bash
python -m playwright install chromium
```

### 3. Set Environment Variables (Optional)

For AI refinement features:

```bash
export MANUS_API_KEY="your_manus_api_key_here"
```

## Usage

### Starting the Server

```bash
python3 app.py
```

The server will start on `http://127.0.0.1:5050`

> Note: `app_enhanced.py` exists in the repo, but the primary UI shown in screenshots
> (HAR upload + Live Traffic Capture tabs) is served by `phishcreator/app.py`.

### API Endpoints

#### 1. Start Live Traffic Analysis

```bash
curl -X POST http://localhost:5000/api/live/start \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://login.example.com",
    "wait_time": 30
  }'
```

**Response:**
```json
{
  "success": true,
  "session_id": "abc123...",
  "message": "Live analysis session started. Browser will open for 30 seconds.",
  "target_url": "https://login.example.com"
}
```

#### 2. Check Session Status

```bash
curl http://localhost:5000/api/live/status/abc123...
```

**Response:**
```json
{
  "session_id": "abc123...",
  "status": "completed",
  "target_url": "https://login.example.com"
}
```

#### 3. Generate Phishlet

**JSON (live-only):**

```bash
curl -X POST http://127.0.0.1:5050/api/live/generate-phishlet/abc123... \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example"
  }'
```

**Multipart (live + authenticated HAR merge):**

Use this when live capture is incomplete or you want to enrich the final YAML with
additional post-login calls/hosts/cookies captured in an authenticated HAR.

```bash
curl -X POST http://127.0.0.1:5050/api/live/generate-phishlet/abc123... \
  -F "name=example" \
  -F "auth_har=@/path/to/authenticated.har"
```

When multipart is used successfully, the response includes:
- `generation_method: "generated_from_live_plus_har"`
- `used_authenticated_har: true`

**Response:**
```json
{
  "success": true,
  "session_id": "abc123...",
  "filename": "intelligent_example_xyz.yaml",
  "confidence": 0.92,
  "auth_flow_type": "api_driven",
  "warnings": ["..."],
  "recommendations": ["..."],
  "yaml_preview": "min_ver: '3.3.0'\nproxy_hosts:\n..."
}
```

#### 4. Download Generated Phishlet

```bash
curl -O http://localhost:5000/api/live/download/abc123...
```

#### 5. Refine with AI (Optional)

```bash
curl -X POST http://localhost:5000/api/live/refine-ai/abc123... \
  -H "Content-Type: application/json" \
  -d '{
    "manus_api_key": "your_api_key"
  }'
```

**Response:**
```json
{
  "success": true,
  "task_id": "task_xyz",
  "task_url": "https://manus.im/task/xyz",
  "share_url": "https://manus.im/share/xyz",
  "message": "AI refinement task created. Check task URL for results."
}
```

#### 6. Record Test Results (Self-Improvement)

```bash
curl -X POST http://localhost:5000/api/learning/record-test \
  -H "Content-Type: application/json" \
  -d '{
    "phishlet_name": "example",
    "target_domain": "example.com",
    "auth_type": "api_driven",
    "success": true,
    "credential_capture": true,
    "cookie_capture": true,
    "confidence_score": 0.92
  }'
```

#### 7. Get Improvement Suggestions

```bash
curl http://localhost:5000/api/learning/suggestions/example.com/api_driven
```

#### 8. Export Learning Data

```bash
curl -O http://localhost:5000/api/learning/export
```

## Workflow Example

### Complete Phishlet Generation Workflow

```bash
# 1. Start live analysis
SESSION_ID=$(curl -s -X POST http://localhost:5000/api/live/start \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://login.example.com", "wait_time": 30}' | jq -r '.session_id')

echo "Session ID: $SESSION_ID"

# 2. Wait for user to complete authentication in the browser
# (Browser will open automatically for 30 seconds)
sleep 35

# 3. Check status
curl http://localhost:5000/api/live/status/$SESSION_ID

# 4. Generate phishlet
curl -X POST http://localhost:5000/api/live/generate-phishlet/$SESSION_ID \
  -H "Content-Type: application/json" \
  -d '{"name": "example", "domain": "example.com"}'

# 5. Download phishlet
curl -O http://localhost:5000/api/live/download/$SESSION_ID

# 6. (Optional) Refine with AI
curl -X POST http://localhost:5000/api/live/refine-ai/$SESSION_ID \
  -H "Content-Type: application/json" \
  -d '{"manus_api_key": "your_key"}'
```

## Module Details

### Live Traffic Analyzer

Captures authentication flows using Playwright:
- Launches headless or visible browser
- Monitors all HTTP requests/responses
- Detects form submissions and credential fields
- Captures cookies from all domains
- Identifies proxy hosts and authentication tokens

### Intelligent Modules

**Auth Flow Classifier**: Scores requests to determine authentication type (form-based, API-driven, OAuth, SAML, multi-step)

**Credential Extractor**: Uses three-tier approach (form fields → JSON analysis → regex) to find credentials

**Cookie Analyzer**: Scores cookies by name patterns and attributes (HttpOnly, Secure, expiry) to prioritize authentication cookies

**Dynamic Generator**: Synthesizes complete phishlets by combining all analysis results

### Self-Improvement Engine

SQLite-based learning system that:
- Records test results (success/failure, captured credentials, captured cookies)
- Builds pattern database indexed by domain and auth type
- Suggests improvements based on historical data
- Exports/imports learning data for team sharing

### AI Refiner

Integrates with Manus AI API to:
- Validate phishlet structure
- Optimize proxy hosts, sub-filters, and cookie capture
- Generate complex regex patterns
- Suggest advanced anti-detection bypasses

## Testing

Run the included test suite:

```bash
python3 -m pytest tests/ -v
```

Or test individual modules:

```bash
python3 modules/auth_flow_classifier.py
python3 modules/intelligent_credential_extractor.py
python3 modules/smart_cookie_analyzer.py
```

## Troubleshooting

### Issue: Playwright not installed

**Solution:**
```bash
pip install playwright
playwright install chromium
```

### Issue: Modules not available

**Solution:** Ensure all modules are in the `modules/` directory and Python can import them:
```bash
ls -la modules/
python3 -c "import sys; sys.path.insert(0, 'modules'); from live_traffic_analyzer import *"
```

### Issue: Low confidence scores

**Solution:** Ensure you capture the complete authentication flow. Missing requests/responses reduce confidence.

### Issue: AI refinement fails

**Solution:** Check your Manus API key and network connectivity:
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" https://api.manus.im/v1/tasks
```

## Security Considerations

1. **API Keys**: Never commit API keys to version control. Use environment variables.
2. **Database**: Protect `phishlet_learning.db` as it contains phishlet performance data.
3. **Temp Files**: The application automatically cleans up temp files after 1 hour.
4. **Network**: Run on a trusted network. The browser automation may expose credentials during capture.

## Advanced Configuration

### Custom Cookie Patterns

Edit `modules/smart_cookie_analyzer.py`:

```python
PRIORITY_PATTERNS = {
    'critical': ['session', 'token', 'auth', 'your_custom_pattern'],
    'important': ['login', 'credential', 'your_pattern']
}
```

### Custom Credential Patterns

Edit `modules/intelligent_credential_extractor.py`:

```python
USERNAME_PATTERNS = ['username', 'user', 'email', 'your_field']
PASSWORD_PATTERNS = ['password', 'passwd', 'pass', 'your_field']
```

### Adjust Wait Time

Increase browser wait time for slow sites:

```json
{
  "target_url": "https://slow-site.com",
  "wait_time": 60
}
```

## License

This tool is intended for authorized penetration testing and red team operations only. Use responsibly and with proper authorization.

## Support

For issues, questions, or contributions:
- Check the logs: `tail -f app_enhanced.log`
- Review module documentation in each `.py` file
- Test individual modules independently
- Export learning data for debugging: `/api/learning/export`

---

**PhishCreator Pro** - Making phishlet generation intelligent, adaptive, and effortless.
