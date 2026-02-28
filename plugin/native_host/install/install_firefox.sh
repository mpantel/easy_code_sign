#!/bin/bash
# Install EasySign Native Messaging Host for Firefox

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_NAME="com.easysign.host"

# Detect host executable path
if [ -f "$SCRIPT_DIR/../dist/easy_sign_host" ]; then
  # Use packaged binary
  HOST_PATH="$SCRIPT_DIR/../dist/easy_sign_host"
elif [ -f "$SCRIPT_DIR/../src/easy_sign_host.rb" ]; then
  # Use Ruby script directly (development mode)
  HOST_PATH="$SCRIPT_DIR/../src/easy_sign_host.rb"
  chmod +x "$HOST_PATH"
else
  echo "Error: Native host executable not found"
  exit 1
fi

HOST_PATH="$(cd "$(dirname "$HOST_PATH")" && pwd)/$(basename "$HOST_PATH")"

# Get extension ID (Firefox uses email-style IDs)
EXTENSION_ID="${EASYSIGN_EXTENSION_ID:-easysign@example.com}"

# Determine manifest directory based on OS
case "$(uname -s)" in
  Darwin)
    # macOS
    if [ "$USER" = "root" ]; then
      MANIFEST_DIR="/Library/Application Support/Mozilla/NativeMessagingHosts"
    else
      MANIFEST_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    fi
    ;;
  Linux)
    # Linux
    if [ "$USER" = "root" ]; then
      MANIFEST_DIR="/usr/lib/mozilla/native-messaging-hosts"
    else
      MANIFEST_DIR="$HOME/.mozilla/native-messaging-hosts"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Windows (Git Bash, MSYS2, Cygwin)
    MANIFEST_DIR="$APPDATA/Mozilla/NativeMessagingHosts"
    ;;
  *)
    echo "Error: Unsupported operating system"
    exit 1
    ;;
esac

# Create manifest directory if it doesn't exist
mkdir -p "$MANIFEST_DIR"

# Generate manifest (Firefox uses allowed_extensions instead of allowed_origins)
MANIFEST_PATH="$MANIFEST_DIR/$HOST_NAME.json"

cat > "$MANIFEST_PATH" << EOF
{
  "name": "$HOST_NAME",
  "description": "EasySign PDF Signing Native Host",
  "path": "$HOST_PATH",
  "type": "stdio",
  "allowed_extensions": [
    "$EXTENSION_ID"
  ]
}
EOF

echo "EasySign Native Messaging Host installed for Firefox"
echo "  Manifest: $MANIFEST_PATH"
echo "  Host: $HOST_PATH"
echo ""
echo "NOTE: Update the extension ID in the manifest if needed:"
echo "  Current: $EXTENSION_ID"
echo ""
echo "To update, run:"
echo "  EASYSIGN_EXTENSION_ID=your_extension_id $0"
