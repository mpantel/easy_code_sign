# EasySign Browser Extension - Installation Guide

This guide covers installing the EasySign browser extension and native messaging host for end users.

## Prerequisites

Before installing EasySign, ensure you have:

1. **Hardware Token**: SafeNet eToken (or compatible PKCS#11 device)
2. **Token Drivers**: SafeNet Authentication Client installed
3. **Browser**: Chrome 88+ or Firefox 78+

## Quick Install

### Step 1: Install Browser Extension

**Chrome:**
1. Download `easysign-chrome.zip` from the releases page
2. Open `chrome://extensions`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select the extracted extension folder

**Firefox:**
1. Download `easysign-firefox.xpi` from the releases page
2. Open `about:addons`
3. Click the gear icon → "Install Add-on From File..."
4. Select the downloaded `.xpi` file

### Step 2: Install Native Host

The native host enables the extension to communicate with your hardware token.

**macOS:**
```bash
# Download and run installer
curl -L https://github.com/mpantel/easy_code_sign/releases/latest/download/install-macos.sh | bash
```

**Linux:**
```bash
# Download and run installer
curl -L https://github.com/mpantel/easy_code_sign/releases/latest/download/install-linux.sh | bash
```

**Windows:**
1. Download `easysign-native-host-windows.exe` from releases
2. Run the installer as Administrator
3. Follow the installation wizard

### Step 3: Verify Installation

1. Open any website (e.g., `https://example.com`)
2. Open browser Developer Tools (F12)
3. In Console, type:
   ```javascript
   window.EasySign.isAvailable().then(console.log)
   ```
4. You should see:
   ```javascript
   { available: true, tokenPresent: true, slots: [...] }
   ```

## Manual Installation

If automatic installation doesn't work, follow these manual steps:

### Install Native Host Manually

**macOS - Chrome:**
```bash
# Create directory
mkdir -p ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts

# Copy manifest (edit paths first!)
cat > ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.easysign.host.json << 'EOF'
{
  "name": "com.easysign.host",
  "description": "EasySign PDF Signing Native Host",
  "path": "/path/to/easy_sign_host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
}
EOF
```

**macOS - Firefox:**
```bash
mkdir -p ~/Library/Application\ Support/Mozilla/NativeMessagingHosts

cat > ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/com.easysign.host.json << 'EOF'
{
  "name": "com.easysign.host",
  "description": "EasySign PDF Signing Native Host",
  "path": "/path/to/easy_sign_host",
  "type": "stdio",
  "allowed_extensions": ["easysign@example.com"]
}
EOF
```

**Linux - Chrome:**
```bash
mkdir -p ~/.config/google-chrome/NativeMessagingHosts
# Copy manifest as above
```

**Linux - Firefox:**
```bash
mkdir -p ~/.mozilla/native-messaging-hosts
# Copy manifest as above
```

**Windows:**
1. Copy `easy_sign_host.exe` to `C:\Program Files\EasySign\`
2. Create registry key:
   - Chrome: `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.easysign.host`
   - Firefox: `HKCU\Software\Mozilla\NativeMessagingHosts\com.easysign.host`
3. Set default value to manifest path

## Troubleshooting

### Extension Not Working

**"Native host not found" error:**
- Verify the native host manifest is in the correct location
- Check that the `path` in the manifest points to the actual executable
- Ensure the executable has execute permissions (`chmod +x`)

**"Token not found" error:**
- Check that your hardware token is connected
- Verify SafeNet drivers are installed
- Try running `pkcs11-tool --list-slots` to verify token visibility

**Extension icon is grayed out:**
- The extension may be disabled - check `chrome://extensions`
- Try removing and re-adding the extension

### Permission Issues

**macOS Gatekeeper blocks native host:**
```bash
# Allow the native host to run
xattr -d com.apple.quarantine /path/to/easy_sign_host
```

**Linux permission denied:**
```bash
# Ensure executable permission
chmod +x /path/to/easy_sign_host
```

### Getting Extension ID

**Chrome:**
1. Go to `chrome://extensions`
2. Enable "Developer mode"
3. The ID is shown under the extension name

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`
2. Find EasySign in the list
3. The ID is shown as "Extension ID"

## Updating

### Update Extension
- Chrome: Will auto-update from Web Store
- Firefox: Will auto-update from Add-ons

### Update Native Host
Run the installer again - it will replace the existing installation.

## Uninstalling

### Remove Extension
- Chrome: Go to `chrome://extensions`, click "Remove"
- Firefox: Go to `about:addons`, click "Remove"

### Remove Native Host

**macOS/Linux:**
```bash
# Chrome
rm ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.easysign.host.json

# Firefox
rm ~/Library/Application\ Support/Mozilla/NativeMessagingHosts/com.easysign.host.json

# Remove executable
rm /path/to/easy_sign_host
```

**Windows:**
Run the uninstaller or manually delete:
- Registry keys under `NativeMessagingHosts`
- `C:\Program Files\EasySign\` folder

## Security Notes

- The extension only activates on HTTPS sites (and localhost for development)
- Your PIN is never stored - it's entered fresh each time you sign
- The native host runs only when needed and exits after signing
- Private keys never leave your hardware token
