from flask import Flask, render_template
import re

app = Flask(__name__)

LOG_FILE = "C:/Users/abuow/OneDrive/Desktop/cyber-alert-system/logs/sample_auth.log"
FAILED_PATTERN = r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"
SUCCESS_PATTERN = r"Accepted password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"

def parse_log():
    failed = {}
    successful = {}
    users = {}

    with open(LOG_FILE, "r") as f:
        for line in f:
            bad = re.search(FAILED_PATTERN, line)
            good = re.search(SUCCESS_PATTERN, line)
            if bad:
                user = bad.group(2)
                ip = bad.group(3)
                failed[ip] = failed.get(ip, 0) + 1
                users[user] = users.get(user, 0) + 1
            if good:
                user = good.group(2)
                ip = good.group(3)
                successful[ip] = successful.get(ip, 0) + 1
                users[user] = users.get(user, 0) + 1
    return failed, successful, users

@app.route("/")
def dashboard():
    failed, successful, users = parse_log()
    return render_template("dashboard.html", failed=failed, successful=successful, users=users)

if __name__ == "__main__":
    app.run(debug=True)
