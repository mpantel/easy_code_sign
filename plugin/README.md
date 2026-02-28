# EasySign Browser Plugin

Browser extension for signing PDF documents using hardware security tokens (HSM/smart cards).

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Web App (Rails, etc.)                              │
│  window.EasySign.sign(pdfBlob, options)            │
└─────────────────┬───────────────────────────────────┘
                  │ postMessage
┌─────────────────▼───────────────────────────────────┐
│  Content Script (Opal.rb → JS)                      │
│  Bridges page ↔ extension, validates origins        │
└─────────────────┬───────────────────────────────────┘
                  │ chrome.runtime.sendMessage
┌─────────────────▼───────────────────────────────────┐
│  Background Service Worker (Opal.rb → JS)           │
│  Opens PIN popup, manages native connection         │
└─────────────────┬───────────────────────────────────┘
                  │ Native Messaging (JSON over stdio)
┌─────────────────▼───────────────────────────────────┐
│  Native Host (Ruby → Packaged Binary)               │
│  Uses EasyCodeSign gem for actual signing           │
│  Accesses PKCS#11 hardware token                    │
└─────────────────────────────────────────────────────┘
```

## Development Setup

### Prerequisites

- Ruby 3.2+
- Node.js (optional, for alternative build tools)
- Chrome or Firefox browser

### Install Dependencies

```bash
cd plugin
bundle install
```

### Build Extension

```bash
# Build all components
bundle exec rake build

# Watch for changes during development
bundle exec rake watch

# Clean build artifacts
bundle exec rake clean
```

### Load Extension in Browser

**Chrome:**
1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `plugin/dist` directory

**Firefox:**
1. Open `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select `plugin/dist/manifest.json`

### Install Native Host (Development)

```bash
# For Chrome
./native_host/install/install_chrome.sh

# For Firefox
./native_host/install/install_firefox.sh
```

## Web App Integration

### Check Availability

```javascript
window.EasySign.isAvailable()
  .then(result => {
    console.log('Extension installed:', result.available);
    console.log('Token connected:', result.tokenPresent);
    console.log('Available slots:', result.slots);
  })
  .catch(err => {
    console.error('EasySign not available:', err);
  });
```

### Sign a PDF

```javascript
// Get PDF as Blob (from file input, fetch, etc.)
const pdfBlob = await fetch('/document.pdf').then(r => r.blob());

// Sign the PDF
window.EasySign.sign(pdfBlob, {
  reason: 'Approved',
  location: 'New York',
  visibleSignature: true,
  signaturePosition: 'bottom_right',
  timestamp: true
})
.then(result => {
  console.log('Signed by:', result.signer_name);
  console.log('Signed at:', result.signed_at);

  // Download signed PDF
  const url = URL.createObjectURL(result.blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'signed_document.pdf';
  a.click();

  // Or upload to server
  const formData = new FormData();
  formData.append('signed_pdf', result.blob, 'signed.pdf');
  fetch('/upload', { method: 'POST', body: formData });
})
.catch(err => {
  console.error('Signing failed:', err.message, err.code);
});
```

### Verify a Signed PDF

```javascript
window.EasySign.verify(signedPdfBlob)
  .then(result => {
    if (result.payload.valid) {
      console.log('Signature is valid!');
      console.log('Signer:', result.payload.signerName);
    } else {
      console.log('Signature invalid:', result.payload.errors);
    }
  });
```

## API Reference

### `window.EasySign.isAvailable()`

Check if extension is installed and token is connected.

**Returns:** `Promise<Object>`
- `available` (boolean): Extension is installed and native host is connected
- `tokenPresent` (boolean): Hardware token is connected
- `slots` (Array): List of available token slots

### `window.EasySign.sign(pdfBlob, options)`

Sign a PDF document. Opens PIN entry popup.

**Parameters:**
- `pdfBlob` (Blob): The PDF file to sign
- `options` (Object):
  - `reason` (string): Reason for signing
  - `location` (string): Location of signing
  - `visibleSignature` (boolean): Add visible signature annotation
  - `signaturePosition` (string): Position (`top_left`, `top_right`, `bottom_left`, `bottom_right`)
  - `signaturePage` (number): Page number for signature (default: 1)
  - `timestamp` (boolean): Add RFC 3161 timestamp

**Returns:** `Promise<Object>`
- `blob` (Blob): Signed PDF file
- `signer_name` (string): Name from signing certificate
- `signed_at` (string): ISO 8601 timestamp
- `timestamped` (boolean): Whether timestamp was added

### `window.EasySign.verify(pdfBlob, options)`

Verify a signed PDF document.

**Parameters:**
- `pdfBlob` (Blob): The signed PDF file
- `options` (Object):
  - `checkTimestamp` (boolean): Verify timestamp (default: true)

**Returns:** `Promise<Object>` with verification details

## Error Handling

```javascript
window.EasySign.sign(pdfBlob, options)
  .catch(err => {
    switch (err.code) {
      case 'TOKEN_NOT_FOUND':
        alert('Please connect your hardware token');
        break;
      case 'PIN_INCORRECT':
        alert('Incorrect PIN');
        break;
      case 'TOKEN_LOCKED':
        alert('Token is locked. Contact administrator.');
        break;
      case 'CANCELLED':
        // User cancelled - no action needed
        break;
      default:
        alert('Signing failed: ' + err.message);
    }
  });
```

## Building for Production

### Package Native Host

The native host can be packaged as a self-contained executable:

```bash
cd native_host
bundle exec rake build:package
```

This creates platform-specific binaries in `native_host/dist/`.

### Create Installer

```bash
# macOS
./create_installer_macos.sh

# Windows
./create_installer_windows.bat

# Linux
./create_installer_linux.sh
```

## Security

- PIN is entered only in browser popup, never on web pages
- PIN is passed directly to native host, never stored
- Origin validation restricts which websites can use the API
- All signing happens in the native host, private keys never leave the token

## License

MIT License - See LICENSE file
