import time
import requests
import sys
import random

def stream_real_logs(filepath):
    url = "http://127.0.0.1:5002/api/stream"
    print(f"Reading real logs from: {filepath}")
    print(f"Streaming to: {url}")
    print("Press Ctrl+C to stop.")

    try:
        with open(filepath, 'r') as f:
            for line in f:
                log_line = line.strip()
                if not log_line:
                    continue

                try:
                    requests.post(url, json={"log": log_line})
                    print(f"Emit -> {log_line[:60]}...")
                except requests.exceptions.ConnectionError:
                    print("Connection failed. Is the Flask server fully running?")
                    time.sleep(2)

                time.sleep(random.uniform(0.1, 1.5))
    except FileNotFoundError:
        print(f"Error: Could not find file {filepath}")
        print("Tip: Have you generated logs yet? Run: python scripts/generate_sample_logs.py")
    except KeyboardInterrupt:
        print("\nStreaming stopped.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        stream_real_logs(sys.argv[1])
    else:
        print("Usage: python scripts/live_stream.py <path_to_log_file>")
        print("Example: python scripts/live_stream.py sample_logs/access.log")
