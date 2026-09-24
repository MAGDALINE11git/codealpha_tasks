# Secure Coding Review Project

This project demonstrates a complete **Secure Coding Review** workflow, featuring an intentionally vulnerable web application, an automated Static Application Security Testing (SAST) tool, and a real-time continuous scanner.

## Features

1. **Vulnerable Target Application (`app.py`)**: A Flask-based web application built with intentional security flaws:
   - SQL Injection (SQLi)
   - Command Injection
   - Cross-Site Scripting (XSS)

2. **Automated Secure Reviewer (`secure_reviewer.py`)**: A static analysis script that automatically scans the codebase using `bandit`. It generates a comprehensive markdown report detailing the found vulnerabilities, risk levels, and specific remediation steps.

3. **Real-Time Continuous Scanner (`realtime_scanner.py`)**: A background watcher utilizing `watchdog`. It monitors the workspace and instantly runs a security scan the moment a developer saves a Python file, providing real-time feedback in the terminal.

## Setup Instructions

This project uses `uv` for fast dependency management.

1. Clone the repository:
   ```bash
   git clone https://github.com/MAGDALINE11git/secure-coding-reviews.git
   cd secure-coding-reviews
   ```

2. Install dependencies and activate the environment:
   ```bash
   uv sync
   # Or using pip directly:
   pip install flask bandit watchdog colorama
   ```

## How to Run

### 1. Run the Automated Scanner
To scan the target file and generate a report (`report.md`):
```bash
python secure_reviewer.py app.py -o report.md
```

### 2. Run the Real-Time Scanner
To monitor the directory and scan files the moment they are saved:
```bash
python realtime_scanner.py
```
*(Try making a change to `app.py` and pressing Save while this is running!)*

### 3. Run the Vulnerable Web App
To start the vulnerable application and test the exploits manually:
```bash
python app.py
```
The server will start at `http://127.0.0.1:5000`.

## Disclaimer
This project is for educational purposes only. Do not deploy the vulnerable application in a production environment.
