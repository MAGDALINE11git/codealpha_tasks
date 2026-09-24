import argparse
import subprocess
import json
import os
from datetime import datetime

def run_bandit(target_path):
    print(f"[*] Running Static Analysis (Bandit) on {target_path}...")
    try:
        result = subprocess.run(
            ['bandit', '-r', target_path, '-f', 'json'],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("[-] Error: Bandit is not installed or not in PATH.")
        return None
    except json.JSONDecodeError:
        print("[-] Error parsing Bandit output.")
        return None

def generate_report(bandit_data, output_file):
    if not bandit_data:
        return
    
    metrics = bandit_data.get('metrics', {})
    results = bandit_data.get('results', [])
    
    with open(output_file, 'w') as f:
        f.write("# Secure Coding Review Report\n\n")
        f.write(f"**Date Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## 1. Scan Summary\n")
        f.write(f"- **Total Vulnerabilities Found:** {len(results)}\n")
        
        if '_totals' in metrics:
            totals = metrics['_totals']
            f.write(f"- **High Severity:** {totals.get('SEVERITY.HIGH', 0)}\n")
            f.write(f"- **Medium Severity:** {totals.get('SEVERITY.MEDIUM', 0)}\n")
            f.write(f"- **Low Severity:** {totals.get('SEVERITY.LOW', 0)}\n\n")
            
        f.write("## 2. Detailed Findings & Remediation\n\n")
        
        if not results:
            f.write("No vulnerabilities found! Excellent job.\n")
        
        for i, issue in enumerate(results, 1):
            f.write(f"### Finding {i}: {issue.get('issue_text')}\n")
            f.write(f"- **Severity:** {issue.get('issue_severity')} | **Confidence:** {issue.get('issue_confidence')}\n")
            f.write(f"- **File:** `{issue.get('filename')}` (Line {issue.get('line_number')})\n\n")
            
            f.write("**Vulnerable Code Snippet:**\n")
            f.write("```python\n")
            f.write(issue.get('code', 'N/A').strip() + "\n")
            f.write("```\n\n")
            
            f.write("**Remediation Advice:**\n")
            test_id = issue.get('test_id')
            if test_id == 'B608':
                f.write("> **SQL Injection:** Avoid string concatenation (`f-strings` or `%s`) when building SQL queries. Use parameterized queries/prepared statements provided by your database driver (e.g., `cursor.execute(\"SELECT * FROM users WHERE user=?\", (user,))`).\n\n")
            elif test_id == 'B602' or test_id == 'B605':
                f.write("> **Command Injection:** Avoid using `shell=True`. Pass commands and arguments as a list of strings (e.g., `subprocess.run(['ping', '-c', '1', ip])`). Validate and sanitize user input before passing it to system commands.\n\n")
            else:
                f.write(f"> Review the usage of `{issue.get('test_name')}`. Ensure proper input validation and sanitization.\n\n")
            f.write("---\n\n")

    print(f"[+] Security report generated successfully: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Automated Secure Coding Review Tool")
    parser.add_argument("target", help="File or directory to audit")
    parser.add_argument("-o", "--output", default="audit_report.md", help="Output markdown report file")
    
    args = parser.parse_args()
    
    target_path = args.target
    if not os.path.exists(target_path):
        print(f"[-] Target path does not exist: {target_path}")
        return

    data = run_bandit(target_path)
    if data is not None:
        generate_report(data, args.output)

if __name__ == "__main__":
    main()
