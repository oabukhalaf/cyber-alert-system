from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import time
import re

app = Flask(__name__)
socketio = SocketIO(app)

LOG_FILE = "C:/Users/abuow/OneDrive/Desktop/cyber-alert-system/logs/sample_auth.log"
FAILED_PATTERN = r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"
seen_lines = set()

def tail_log_file():
    print(f"🔍 Watching file: {LOG_FILE}")
    last_position = 0

    while True:
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(last_position)  # Move to last read position
                new_lines = f.readlines()
                last_position = f.tell()  # Update last read position

                for line in new_lines:
                    print("👀 Detected new line:", line.strip())
                    match = re.search(FAILED_PATTERN, line)
                    if match:
                        ip = match.group(3)
                        user = match.group(2)
                        alert = f"🚨 Failed login by {user} from {ip}"
                        print("📢 Sending alert:", alert)
                        socketio.emit("new_alert", alert)
        except Exception as e:
            print("❌ Error:", e)

        time.sleep(2)


@app.route("/")
def index():
    return render_template("live_dashboard.html")

if __name__ == "__main__":
    watcher_thread = threading.Thread(target=tail_log_file)
    watcher_thread.daemon = True
    watcher_thread.start()
    socketio.run(app, debug=True)
