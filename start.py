import os
import socket
import subprocess
import sys
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

url = urlparse(os.environ.get("APP_BASE_URL", "http://localhost:5000"))
port = int(os.environ.get("PORT", url.port or 5000))

if port < 1 or port > 65535:
    print(f"Invalid PORT: {port}. Must be a number between 1 and 65535.")
    sys.exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("", port))
    sock.close()
    print(f"✅ Port {port} is available.")
except OSError:
    print(
        f"\n❌ The port {port} that is configured in Auth0 is currently in use.\n"
        "\nTo resolve this issue:"
        f"\n1. Free up port {port} by stopping the application using it, OR"
        "\n2. Configure URLs with a new port in your Auth0 application settings:"
        "\n   - Allowed Callback URLs"
        "\n   - Allowed Logout URLs"
        "\n   Then update the PORT environment variable accordingly\n"
    )
    sys.exit(1)

sys.exit(subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "server.py")]).returncode)
