import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return "<h1>Welcome to the intentionally vulnerable app!</h1>"

# 1. Vulnerable to SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABILITY: String concatenation allows SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return "Logged in successfully!"
        else:
            return "Invalid credentials."
    except Exception as e:
        return f"Database error: {e}"

# 2. Vulnerable to Command Injection
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '')
    if ip:
        # VULNERABILITY: User input directly executed in a shell command
        cmd = f"ping -c 1 {ip}"
        try:
            result = subprocess.check_output(cmd, shell=True, text=True)
            return f"<pre>{result}</pre>"
        except Exception as e:
            return f"Command execution failed."
    return "Please provide an IP address, e.g., ?ip=127.0.0.1"

# 3. Vulnerable to Cross-Site Scripting (XSS)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # VULNERABILITY: User input directly rendered in HTML
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)
hiiii