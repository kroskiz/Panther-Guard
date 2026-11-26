# Panther-Guard

A desktop security helper for FIU students. Java scans running processes and logs security events; a Streamlit dashboard (with Roary the panther as your AI helper) shows what it found.

## Project structure

```
Panther-Guard/
├── app.py              # Streamlit dashboard (main entry point)
├── roary_helper.py     # Roary AI helper panel
├── run_app.bat         # One-click start (Windows)
├── run_app.sh          # One-click start (Mac/Linux)
├── src/                # Java source (ProcessScanner, Logger)
├── bin/                # Compiled Java classes (created by the run script)
├── data/               # ipc_spec.json, security_logs.json
└── assets/             # Roary mascot images
```

## Prerequisites

Install these first, then confirm each one works with the version command shown.

| Tool | Why | Check |
|------|-----|-------|
| Git | Clone the repo and push your branch | `git --version` |
| Java JDK 17 or newer | Compile and run the Java scanner | `javac -version` |
| Python 3.10 or newer | Runs the Streamlit dashboard | `python --version` |
| VS Code | Recommended editor | n/a |

## Setup

### 1. Install VS Code
Download from https://code.visualstudio.com and install these extensions: **Extension Pack for Java** and **Python**.

### 2. Install Git
Download from https://git-scm.com and keep the default options. Then set your identity once:

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

### 3. Install Java (JDK)
Install a JDK (17 or newer), for example Temurin from https://adoptium.net. Make sure `javac -version` works in a new terminal. If it doesn't, the JDK's `bin` folder is not on your PATH.

### 4. Install Streamlit
```bash
pip install streamlit
```

### 5. Clone the repo
```bash
git clone https://github.com/kroskiz/Panther-Guard.git
cd Panther-Guard
```
Open the folder in VS Code (`code .`).

## Run the app

**Windows:** double-click `run_app.bat`, or run it from a terminal.

**Mac/Linux:**
```bash
chmod +x run_app.sh
./run_app.sh
```

The script compiles the Java files and launches Streamlit. Your browser should open at http://localhost:8501.

To run only the dashboard:
```bash
streamlit run app.py
```

## Contributing (team workflow)

1. Never commit directly to `main`.
2. Create a feature branch named after your role:
   ```bash
   git checkout -b feature/member-<number>-<short-name>
   ```
3. Commit small and often:
   ```bash
   git add .
   git commit -m "Describe what you changed"
   git push -u origin feature/member-<number>-<short-name>
   ```
4. Open a Pull Request on GitHub and ask a teammate to review.
5. Update your card on the Trello **Weekly Tasks** board.

6. ## Setup
 Steps:
1. Install Python 3.9+ and Java (JDK).
2. Install dependencies:
   pip install streamlit google-genai jsonschema
3. Get a free Gemini API key from Google AI Studio.
4. Set the key in your terminal (do NOT commit it):
   - PowerShell: $env:GEMINI_API_KEY = "your-key"
   - cmd: set GEMINI_API_KEY=your-key
   Set it in the same terminal you run the app from.
5. Run the dashboard:
   python -m streamlit run roary_helper.py

## Roary AI Helper
Roary answers security questions using the events in data/security_logs.json.
The model name is the GEMINI_MODEL constant in roary_helper.py. If you see a
404 "model not found" error, update it to a currently available model.
A 503 error means Google is busy; Roary shows a fallback message and you can retry.

## Java scanner
Compile ProcessScanner.java, then run:
   java -cp bin ProcessScanner path/to/output.json
On failure or timeout it writes mock data and prints the reason to stderr.

## Validate output
   python validate_ipc.py path/to/output.json

## Troubleshooting

- **`javac` not recognized:** reinstall the JDK or add its `bin` folder to PATH, then open a new terminal.
- **`streamlit` not recognized:** try `python -m streamlit run app.py`.
- **Port already in use:** run `streamlit run app.py --server.port 8502`.
- **Missing Roary images:** check that `assets/` contains `roary_safe.png`, `roary_warning.png` and `roary_alert.png`.
