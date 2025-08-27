Overview

The Cyber Alert System is a lightweight security monitoring tool designed to parse system logs and provide real-time visualization of potential threats. It helps detect failed login attempts, suspicious activity, and other security-related events through an interactive dashboard.

Features

- Log Parsing: Automatically scans and extracts key security events from system logs.
- Real-Time Monitoring: Live dashboard that updates as new log entries appear.
- Interactive Visuals: Web-based UI for easy viewing and monitoring.
- Sample Logs Included: Comes with a sample log file for testing.

Project Structure
cyber-alert-system/
    dashboard.py             # Renders dashboard views
    log_parser.py            # Parses and processes log files
    realtime_dashboard.py    # Hosts live dashboard with real-time updates
    realtime_log_tracker.py  # Tracks log changes continuously
    requirements.txt         # Python dependencies
    logs/
        sample_auth.log      # Sample log file for demonstration
        placeholder
    templates/
        dashboard.html       # Static dashboard template
        live_dashboard.html  # Live dashboard template
        placeholder


Installation & Usage

1. Install dependencies:
- pip install -r requirements.txt

2. Run the real-time dashboard:
- python realtime_dashboard.py

3. Access the dashboard:
 - Open your browser and navigate to:
      http://127.0.0.1:5000

Requirements
- Python 3.7+
- Flask (for web dashboard)
- Other dependencies listed in requirements.txt

Future Enhancements
- Support for additional log formats.
- Email/SMS alerts for suspicious events.
- Role-based access control.

License
- This project is open-source and available for educational and professional use.
