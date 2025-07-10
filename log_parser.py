import re

# Path to your log file
LOG_FILE = "C:/Users/abuow/OneDrive/Desktop/cyber-alert-system/logs/sample_auth.log"

# Pattern to match failed SSH login attempts
FAILED_LOGIN_PATTERN = r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"
SUCCESSFUL_LOGIN_PATTERN = r"Accepted password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"

def main():
    failed_ips = {}
    successful_ips = {}
    total_usernames = {}

    with open(LOG_FILE, "r") as f:
        for line in f:
            badMatch = re.search(FAILED_LOGIN_PATTERN, line)
            goodMatch = re.search(SUCCESSFUL_LOGIN_PATTERN, line)
            if badMatch:
                invalidUser = badMatch.group(1)
                username = badMatch.group(2)
                ip = badMatch.group(3)
                failed_ips[ip] = failed_ips.get(ip, 0) + 1
                total_usernames[username] = total_usernames.get(username, 0) + 1
            if goodMatch:
                invalidUser = goodMatch.group(1)
                username = goodMatch.group(2)
                ip = goodMatch.group(3)
                successful_ips[ip] = successful_ips.get(ip, 0) + 1
                total_usernames[username] = total_usernames.get(username, 0) + 1

    print("Failed Login Summary:")
    for ip, count in failed_ips.items():
        print(f"  - {ip} failed {count} time(s)")
    print("Successful Login Summary:")
    for ip, count in successful_ips.items():
        print(f"  - {ip} successful {count} time(s)")
    print("Username Login Count Summary:")
    for username, count in total_usernames.items():
        print(f"  - {username} appeared {count} time(s)")


if __name__ == "__main__":
    main()
