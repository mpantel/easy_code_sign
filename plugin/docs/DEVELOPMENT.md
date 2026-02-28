# EasySign Browser Extension - Development Guide

This guide covers building, testing, and extending the EasySign browser extension.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Application                          │
│                   window.EasySign.sign(blob)                   │
└─────────────────────────────┬───────────────────────────────────┘
                              │ window.postMessage
┌─────────────────────────────▼───────────────────────────────────┐
│                     Content Script (Opal)                       │
│  - Injected into every page matching host_permissions          │
│  - Bridges page context ↔ extension context                    │
│  - Validates origin before forwarding messages                 │
└─────────────────────────────┬───────────────────────────────────┘
                              │ chrome.runtime.sendMessage
┌─────────────────────────────▼───────────────────────────────────┐
│                Background Service Worker (Opal)                 │
│  - Manages native messaging connection                         │
│  - Opens PIN popup when signing requested                      │
│  - Correlates requests/responses with IDs                      │
└─────────────────────────────┬───────────────────────────────────┘
                              │ chrome.runtime.connectNative
┌─────────────────────────────▼───────────────────────────────────┐
│                   Native Messaging Host (Ruby)                  │
│  - Stdio JSON protocol (length-prefixed)                       │
│  - Uses EasyCodeSign gem for actual signing                    │
│  - Accesses PKCS#11 hardware token                             │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
plugin/
├── Gemfile                    # Ruby dependencies (Opal, etc.)
├── Rakefile                   # Build tasks
├── README.md                  # User documentation
│
├── src/                       # Opal Ruby source files
│   └── easy_sign/
│       ├── messaging.rb       # Protocol constants & helpers
│       ├── background.rb      # Service worker
│       ├── content.rb         # Content script
│       ├── inject.rb          # Page-injected API
│       └── popup.rb           # PIN popup controller
│
├── templates/                 # Static files
│   ├── manifest.json          # WebExtension manifest
│   ├── popup.html             # PIN entry popup
│   └── popup.css              # Popup styles
│
├── dist/                      # Built extension (gitignored)
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── inject.js
│   └── popup/
│
├── native_host/               # Native messaging host
│   ├── src/
│   │   ├── easy_sign_host.rb  # Main entry point
│   │   ├── protocol.rb        # Message protocol
│   │   └── signing_service.rb # EasyCodeSign wrapper
│   ├── install/               # Installation scripts
│   └── test/                  # Native host tests
│
├── docs/                      # Documentation
└── test/                      # Extension tests
```

## Development Setup

### Prerequisites

- Ruby 3.2+
- Bundler
- Chrome or Firefox
- EasyCodeSign gem installed (for native host)

### Install Dependencies

```bash
cd plugin
bundle install
```

### Build Extension

```bash
# Full build
bundle exec rake build

# Individual components
bundle exec rake build:background
bundle exec rake build:content
bundle exec rake build:inject
bundle exec rake build:popup
bundle exec rake build:manifest
bundle exec rake build:assets

# Watch mode (auto-rebuild on changes)
bundle exec rake watch

# Clean build
bundle exec rake clean
```

### Load Extension in Browser

**Chrome:**
1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `plugin/dist` directory
5. Note the Extension ID (needed for native host)

**Firefox:**
1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `plugin/dist/manifest.json`

### Install Native Host (Development)

```bash
# Set your extension ID
export EASYSIGN_EXTENSION_ID=your_chrome_extension_id

# Install for Chrome
./native_host/install/install_chrome.sh

# Or for Firefox
export EASYSIGN_EXTENSION_ID=easysign@example.com
./native_host/install/install_firefox.sh
```

## Opal.rb Development

The extension is written in Ruby and compiled to JavaScript using [Opal](https://opalrb.com/).

### Key Concepts

**1. JavaScript Interop:**
```ruby
# backtick_javascript: true  # Required at top of file

# Call JavaScript directly
`console.log("Hello from Opal")`

# Access JS objects
`chrome.runtime.sendMessage(#{message.to_n})`

# Convert Ruby to JS native object
message.to_n

# Access JS result in Ruby
result = `document.getElementById('my-id')`
```

**2. Native Module:**
```ruby
require "native"

# Wrap JS objects
class ChromeStorage
  include Native::Wrapper

  def get(key)
    promise = Promise.new
    `chrome.storage.local.get(#{key}, function(result) {
      #{promise.resolve(`result`)}
    })`
    promise
  end
end
```

**3. Promises:**
```ruby
require "promise"

def async_operation
  Promise.new do |resolve, reject|
    # Async work...
    resolve.call(result)
    # Or on error:
    reject.call(error)
  end
end
```

### File Structure

Each Opal source file needs these magic comments:
```ruby
# frozen_string_literal: true
# backtick_javascript: true

require "native"
require "easy_sign/messaging"

module EasySign
  class MyComponent
    # ...
  end
end
```

## Native Messaging Protocol

### Message Format

Messages are JSON with a 4-byte little-endian length prefix:

```
[4 bytes: length][JSON data]
```

### Request Structure

```json
{
  "type": "sign",
  "requestId": "uuid-string",
  "payload": {
    "pdfData": "base64-encoded-pdf",
    "pin": "1234",
    "options": {
      "reason": "Approved",
      "visibleSignature": true
    }
  }
}
```

### Response Structure

```json
{
  "type": "sign_response",
  "requestId": "uuid-string",
  "payload": {
    "signedPdfData": "base64-encoded-signed-pdf",
    "signerName": "CN=John Doe",
    "signedAt": "2025-01-06T10:30:00Z"
  },
  "error": null
}
```

### Error Response

```json
{
  "type": "error",
  "requestId": "uuid-string",
  "payload": null,
  "error": {
    "code": "PIN_INCORRECT",
    "message": "Incorrect PIN",
    "details": { "retriesRemaining": 2 }
  }
}
```

## Testing

### Native Host Tests

```bash
# Run native host unit tests
cd plugin
ruby -I native_host/src -I ../lib native_host/test/native_host_test.rb
```

### Manual Testing

1. Build and load the extension
2. Open a test page with PDF upload
3. Open DevTools Console
4. Test the API:

```javascript
// Check availability
await window.EasySign.isAvailable()

// Sign a PDF (will open PIN popup)
const input = document.querySelector('input[type=file]');
const blob = input.files[0];
const result = await window.EasySign.sign(blob, { visibleSignature: true });
console.log('Signed:', result);
```

### Test Page

Create a simple test page:

```html
<!DOCTYPE html>
<html>
<head>
  <title>EasySign Test</title>
</head>
<body>
  <h1>EasySign Test</h1>

  <h2>1. Check Availability</h2>
  <button onclick="checkAvailability()">Check</button>
  <pre id="availability"></pre>

  <h2>2. Sign PDF</h2>
  <input type="file" id="pdf-input" accept=".pdf">
  <button onclick="signPdf()">Sign</button>
  <pre id="sign-result"></pre>

  <h2>3. Verify PDF</h2>
  <input type="file" id="signed-pdf-input" accept=".pdf">
  <button onclick="verifyPdf()">Verify</button>
  <pre id="verify-result"></pre>

  <script>
    async function checkAvailability() {
      try {
        const result = await window.EasySign.isAvailable();
        document.getElementById('availability').textContent =
          JSON.stringify(result, null, 2);
      } catch (e) {
        document.getElementById('availability').textContent =
          'Error: ' + e.message;
      }
    }

    async function signPdf() {
      const input = document.getElementById('pdf-input');
      if (!input.files[0]) {
        alert('Please select a PDF file');
        return;
      }

      try {
        const result = await window.EasySign.sign(input.files[0], {
          reason: 'Test signature',
          visibleSignature: true
        });

        document.getElementById('sign-result').textContent =
          JSON.stringify({
            signerName: result.signer_name,
            signedAt: result.signed_at,
            blobSize: result.blob.size
          }, null, 2);

        // Download signed PDF
        const url = URL.createObjectURL(result.blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'signed.pdf';
        a.click();
      } catch (e) {
        document.getElementById('sign-result').textContent =
          'Error: ' + e.code + ' - ' + e.message;
      }
    }

    async function verifyPdf() {
      const input = document.getElementById('signed-pdf-input');
      if (!input.files[0]) {
        alert('Please select a signed PDF file');
        return;
      }

      try {
        const result = await window.EasySign.verify(input.files[0]);
        document.getElementById('verify-result').textContent =
          JSON.stringify(result.payload, null, 2);
      } catch (e) {
        document.getElementById('verify-result').textContent =
          'Error: ' + e.code + ' - ' + e.message;
      }
    }
  </script>
</body>
</html>
```

## Debugging

### Extension Logs

**Chrome:**
1. Go to `chrome://extensions`
2. Find EasySign, click "Service worker"
3. View console logs in DevTools

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`
2. Find EasySign, click "Inspect"

### Native Host Logs

The native host writes to stderr, which browsers typically discard. For debugging:

```ruby
# In native host code
$stderr.puts "Debug: #{message.inspect}"
```

To capture logs, modify the host to write to a file:

```ruby
# At top of easy_sign_host.rb
LOG_FILE = File.open('/tmp/easysign.log', 'a')

def log(message)
  LOG_FILE.puts "[#{Time.now}] #{message}"
  LOG_FILE.flush
end
```

### Content Script Debugging

Content script logs appear in the page's DevTools console:
```ruby
puts "Content script loaded"  # Appears in page console
```

## Extending the Extension

### Adding New Message Types

1. **Define in messaging.rb:**
```ruby
module Types
  MY_NEW_REQUEST = "my_new_request"
  MY_NEW_RESPONSE = "my_new_response"
end
```

2. **Handle in background.rb:**
```ruby
when Messaging::Types::MY_NEW_REQUEST
  handle_my_new_request(message, sender, send_response)
```

3. **Add to native host protocol.rb:**
```ruby
module Types
  MY_NEW = "my_new"
  MY_NEW_RESPONSE = "my_new_response"
end
```

4. **Implement in easy_sign_host.rb:**
```ruby
when Protocol::Types::MY_NEW
  process_my_new(request_id, message[:payload])
```

### Adding Configuration Options

1. **Add to manifest.json:**
```json
"options_ui": {
  "page": "options/options.html",
  "open_in_tab": false
}
```

2. **Create options page**
3. **Store settings with chrome.storage.local**

### Supporting New Token Providers

1. **Add provider to EasyCodeSign gem** (main library)
2. **Configure in native host signing_service.rb:**
```ruby
config.provider = ENV.fetch("EASYSIGN_PROVIDER", "safenet").to_sym
```

## Packaging for Production

### Build Release

```bash
# Clean build
bundle exec rake clean build

# Create ZIP for Chrome Web Store
cd dist
zip -r ../easysign-chrome.zip .

# Create XPI for Firefox (just a ZIP with .xpi extension)
cd dist
zip -r ../easysign-firefox.xpi .
```

### Package Native Host

See [ruby-packer documentation](https://github.com/nicyuxuan/ruby-packer) for creating self-contained executables.

```bash
gem install rubyc
rubyc native_host/src/easy_sign_host.rb -o native_host/dist/easy_sign_host
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

### Code Style

- Follow Ruby style guide
- Use `frozen_string_literal: true`
- Add `# backtick_javascript: true` for Opal files with JS interop
- Document public methods
