import time
import re

LOG_FILE = "C:/Users/abuow/OneDrive/Desktop/cyber-alert-system/logs/sample_auth.log"
FAILED_PATTERN = r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"

seen_lines = set()

def parse_line(line):
    match = re.search(FAILED_PATTERN, line)
    if match:
        ip = match.group(3)
        user = match.group(2)
        print(f"ALERT: Failed login by {user} from {ip}")

def tail_log_file():
    while True:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            new_lines = [line for line in lines if line not in seen_lines]
            for line in new_lines:
                seen_lines.add(line)
                parse_line(line)
        time.sleep(2)  # wait 2 seconds before checking again

if __name__ == "__main__":
    print("Watching log file for changes...")
    tail_log_file()
