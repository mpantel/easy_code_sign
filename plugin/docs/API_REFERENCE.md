# EasySign API Reference

The EasySign browser extension exposes a `window.EasySign` object that web applications can use to sign and verify PDF documents using hardware security tokens.

## Overview

```javascript
// Check if EasySign is available
const status = await window.EasySign.isAvailable();

// Sign a PDF
const result = await window.EasySign.sign(pdfBlob, options);

// Verify a signed PDF
const verification = await window.EasySign.verify(pdfBlob);
```

## Methods

### `window.EasySign.isAvailable()`

Check if the EasySign extension is installed and the hardware token is connected.

**Parameters:** None

**Returns:** `Promise<AvailabilityResult>`

```typescript
interface AvailabilityResult {
  available: boolean;      // Extension and native host are working
  tokenPresent: boolean;   // Hardware token is connected
  slots: TokenSlot[];      // List of available token slots
}

interface TokenSlot {
  index: number;           // Slot index
  tokenLabel: string;      // Token display name
  manufacturer: string;    // Token manufacturer
  serial: string;          // Token serial number
}
```

**Example:**
```javascript
window.EasySign.isAvailable()
  .then(result => {
    if (!result.available) {
      alert('Please install the EasySign extension');
      return;
    }
    if (!result.tokenPresent) {
      alert('Please connect your hardware token');
      return;
    }
    console.log('Ready to sign!', result.slots);
  })
  .catch(err => {
    console.error('EasySign error:', err);
  });
```

---

### `window.EasySign.sign(pdfBlob, options)`

Sign a PDF document. Opens a popup for secure PIN entry.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pdfBlob` | `Blob` | Yes | The PDF file to sign |
| `options` | `SignOptions` | No | Signing options |

```typescript
interface SignOptions {
  // Signature metadata
  reason?: string;              // Reason for signing (e.g., "Approved")
  location?: string;            // Location of signing (e.g., "New York")

  // Visible signature
  visibleSignature?: boolean;   // Add visible signature annotation (default: false)
  signaturePosition?: string;   // Position: "top_left", "top_right", "bottom_left", "bottom_right"
  signaturePage?: number;       // Page number for signature (default: 1)

  // Timestamp
  timestamp?: boolean;          // Add RFC 3161 timestamp (default: false)
  timestampAuthority?: string;  // TSA URL (default: http://timestamp.digicert.com)
}
```

**Returns:** `Promise<SignResult>`

```typescript
interface SignResult {
  blob: Blob;              // The signed PDF file
  signer_name: string;     // Certificate common name
  signed_at: string;       // ISO 8601 timestamp
  timestamped: boolean;    // Whether timestamp was added
}
```

**Example:**
```javascript
// Get PDF from file input
const fileInput = document.getElementById('pdf-file');
const pdfBlob = fileInput.files[0];

// Sign with options
window.EasySign.sign(pdfBlob, {
  reason: 'Document approved',
  location: 'New York, NY',
  visibleSignature: true,
  signaturePosition: 'bottom_right',
  timestamp: true
})
.then(result => {
  console.log('Signed by:', result.signer_name);
  console.log('Signed at:', result.signed_at);

  // Download the signed PDF
  const url = URL.createObjectURL(result.blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'signed_document.pdf';
  link.click();
  URL.revokeObjectURL(url);
})
.catch(err => {
  if (err.code === 'CANCELLED') {
    console.log('User cancelled signing');
  } else {
    console.error('Signing failed:', err.message);
  }
});
```

---

### `window.EasySign.verify(pdfBlob, options)`

Verify a signed PDF document.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pdfBlob` | `Blob` | Yes | The signed PDF file to verify |
| `options` | `VerifyOptions` | No | Verification options |

```typescript
interface VerifyOptions {
  checkTimestamp?: boolean;  // Verify timestamp (default: true)
}
```

**Returns:** `Promise<VerifyResult>`

```typescript
interface VerifyResult {
  payload: {
    valid: boolean;              // Overall signature validity
    signerName: string;          // Certificate common name
    signerOrganization: string;  // Certificate organization
    signedAt: string;            // Signing timestamp (ISO 8601)

    // Detailed checks
    signatureValid: boolean;     // Cryptographic signature OK
    integrityValid: boolean;     // Document not tampered
    certificateValid: boolean;   // Certificate not expired
    chainValid: boolean;         // Certificate chain OK
    trusted: boolean;            // Root CA is trusted

    // Timestamp
    timestamped: boolean;        // Has timestamp
    timestampValid: boolean;     // Timestamp is valid

    // Issues
    errors: string[];            // List of errors
    warnings: string[];          // List of warnings
  }
}
```

**Example:**
```javascript
window.EasySign.verify(signedPdfBlob)
  .then(result => {
    const v = result.payload;

    if (v.valid) {
      console.log('✓ Signature is valid');
      console.log('  Signed by:', v.signerName);
      console.log('  Organization:', v.signerOrganization);
      console.log('  Date:', new Date(v.signedAt).toLocaleString());

      if (v.timestamped) {
        console.log('  Timestamped: Yes');
      }
    } else {
      console.log('✗ Signature is invalid');
      v.errors.forEach(err => console.log('  Error:', err));
    }

    if (v.warnings.length > 0) {
      console.log('Warnings:');
      v.warnings.forEach(w => console.log('  -', w));
    }
  });
```

---

## Error Handling

All methods return Promises that reject with an `Error` object containing a `code` property.

```typescript
interface EasySignError extends Error {
  code: string;  // Error code for programmatic handling
}
```

### Error Codes

| Code | Description | User Action |
|------|-------------|-------------|
| `TOKEN_NOT_FOUND` | Hardware token not connected | Connect token and retry |
| `PIN_INCORRECT` | Wrong PIN entered | Re-enter correct PIN |
| `TOKEN_LOCKED` | Token locked (too many wrong PINs) | Contact administrator |
| `INVALID_PDF` | PDF file is corrupted or invalid | Use a valid PDF file |
| `SIGNING_FAILED` | Signing operation failed | Check token and retry |
| `VERIFICATION_FAILED` | Verification operation failed | Check PDF file |
| `NATIVE_HOST_NOT_FOUND` | Native host not installed | Install native host |
| `TIMEOUT` | Operation timed out | Retry the operation |
| `CANCELLED` | User cancelled the operation | No action needed |
| `ORIGIN_NOT_ALLOWED` | Website not allowed to use EasySign | N/A |
| `INTERNAL_ERROR` | Unexpected error | Report bug |

### Error Handling Example

```javascript
window.EasySign.sign(pdfBlob, options)
  .then(result => {
    // Success
  })
  .catch(err => {
    switch (err.code) {
      case 'TOKEN_NOT_FOUND':
        showMessage('Please connect your hardware token');
        break;

      case 'PIN_INCORRECT':
        showMessage('Incorrect PIN. Please try again.');
        break;

      case 'TOKEN_LOCKED':
        showMessage('Your token is locked. Contact your IT administrator.');
        break;

      case 'CANCELLED':
        // User cancelled - no message needed
        break;

      case 'TIMEOUT':
        showMessage('Operation timed out. Please try again.');
        break;

      default:
        showMessage(`Signing failed: ${err.message}`);
        console.error('EasySign error:', err);
    }
  });
```

---

## TypeScript Definitions

For TypeScript projects, you can use these type definitions:

```typescript
declare global {
  interface Window {
    EasySign: {
      isAvailable(): Promise<{
        available: boolean;
        tokenPresent: boolean;
        slots: Array<{
          index: number;
          tokenLabel: string;
          manufacturer: string;
          serial: string;
        }>;
      }>;

      sign(pdfBlob: Blob, options?: {
        reason?: string;
        location?: string;
        visibleSignature?: boolean;
        signaturePosition?: 'top_left' | 'top_right' | 'bottom_left' | 'bottom_right';
        signaturePage?: number;
        timestamp?: boolean;
        timestampAuthority?: string;
      }): Promise<{
        blob: Blob;
        signer_name: string;
        signed_at: string;
        timestamped: boolean;
      }>;

      verify(pdfBlob: Blob, options?: {
        checkTimestamp?: boolean;
      }): Promise<{
        payload: {
          valid: boolean;
          signerName: string;
          signerOrganization: string;
          signedAt: string;
          signatureValid: boolean;
          integrityValid: boolean;
          certificateValid: boolean;
          chainValid: boolean;
          trusted: boolean;
          timestamped: boolean;
          timestampValid: boolean;
          errors: string[];
          warnings: string[];
        };
      }>;
    };
  }
}
```

Save this as `easysign.d.ts` in your project.

---

## Browser Compatibility

| Browser | Minimum Version | Notes |
|---------|-----------------|-------|
| Chrome | 88+ | Full support |
| Edge | 88+ | Chromium-based, full support |
| Firefox | 78+ | Full support |
| Safari | Not supported | No native messaging API |
| Opera | 74+ | Chromium-based, should work |

---

## Security Considerations

1. **HTTPS Only**: The extension only works on HTTPS sites (except localhost)
2. **PIN Security**: PINs are never stored, only passed directly to the native host
3. **Origin Validation**: Only whitelisted origins can use the API
4. **No Key Export**: Private keys never leave the hardware token

---

## Rate Limiting

There are no rate limits on the API, but:
- Each `sign()` call requires user interaction (PIN entry)
- Native host operations are sequential (one at a time)
- Signing large PDFs may take several seconds
