import time
import subprocess
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import init, Fore, Style

init(autoreset=True)

class SecurityScannerHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_scanned = 0

    def on_modified(self, event):
        # Only scan .py files and ignore the virtual env, hidden files, or the scanner itself
        if not event.is_directory and event.src_path.endswith('.py'):
            if 'realtime_scanner.py' in event.src_path or '.venv' in event.src_path:
                return

            # Debounce to prevent multiple triggers for a single save
            current_time = time.time()
            if current_time - self.last_scanned < 2.0:
                return
            self.last_scanned = current_time

            print(f"\n{Fore.YELLOW}[*] File saved: {os.path.basename(event.src_path)}. Running real-time security scan...{Style.RESET_ALL}")
            self.run_scan(event.src_path)

    def run_scan(self, file_path):
        try:
            # We use text output for the terminal this time instead of JSON
            result = subprocess.run(
                ['bandit', '-r', file_path, '--format', 'txt'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] No vulnerabilities found! Code looks secure.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Vulnerabilities detected!{Style.RESET_ALL}")
                print(result.stdout)
                print(f"{Fore.YELLOW}[!] Fix the above issues to secure your application.{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error running scan: {e}{Style.RESET_ALL}")

def start_watcher(path='.'):
    event_handler = SecurityScannerHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    print(f"{Fore.CYAN}[*] Real-Time Security Scanner started.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Watching directory: {os.path.abspath(path)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Press Ctrl+C to stop.{Style.RESET_ALL}\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\n{Fore.CYAN}[*] Scanner stopped.{Style.RESET_ALL}")
    
    observer.join()

if __name__ == "__main__":
    start_watcher()
