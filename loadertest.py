import requests
import sys

def load_test(url, count=100):
    # Defence: block tip commands
    if isinstance(url, str) and url.strip().startswith('/tip'):
        print(f"[DEFENCE] Tip command blocked: {url}")
        return

    for i in range(count):
        try:
            resp = requests.get(url, timeout=5)
            print(f"[{i}] Status: {resp.status_code}")
        except Exception as e:
            print(f"[{i}] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python loadertest.py <url>")
        sys.exit(1)
    
    target = sys.argv[1]
    try:
        load_test(target)
    except Exception as e:
        print(f"[DEFENCE] Unhandled exception caught: {e}")
