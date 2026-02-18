# chat-secure-guard-js

A complete JavaScript/TypeScript client for End-to-End Encryption (E2EE), secure file encryption, and key management. Compatible with React, Vue, Angular, and Node.js.

## Features

- ✅ **End-to-End Encryption (E2EE)** using `libsodium` (via `libsodium-wrappers`).
- ✅ **Secure Key Management** (Public/Private Key generation & storage).
- ✅ **File Encryption/Decryption** (Symmetric authenticated encryption).
- ✅ **Universal Compatibility** (Browser & Node.js).
- ✅ **Pluggable Secure Storage** (Use `localStorage`, `AsyncStorage`, or custom).

## Installation

```bash
npm install chat-secure-guard-js
```

## Usage

### 1. Initialization

You must initialize the library once before using it. This ensures `libsodium` is ready and keys are loaded/generated.

```typescript
import { ChatSecureGuard, SecureStorageInterface } from 'chat-secure-guard-js';

// Optional: Custom storage implementation (e.g. for React Native or Browser)
// By default, it uses an In-Memory storage (not persistent across reloads).
class MyBrowserStorage implements SecureStorageInterface {
  async write(key: string, value: string) { localStorage.setItem(key, value); }
  async read(key: string) { return localStorage.getItem(key); }
  async delete(key: string) { localStorage.removeItem(key); }
}

// Initialize
const guard = await ChatSecureGuard.init(new MyBrowserStorage());
```

### 2. Key Management

Retrieve your public key to share with other users.

```typescript
const publicKey = await guard.getPublicKey();
// Send `publicKey` (Uint8Array) to your server/other users.
```

### 3. Encrypting Messages

Encrypt a message for a specific recipient using their Public Key.

```typescript
const message = "Hello Secure World";
const receiverPublicKey = ...; // Uint8Array from recipient

const encryptedBase64 = await guard.encrypt(message, receiverPublicKey);
console.log('Encrypted:', encryptedBase64);
```

### 4. Decrypting Messages

Decrypt a message received from a sender.

```typescript
const senderPublicKey = ...; // Uint8Array from sender
const decryptedText = await guard.decrypt(encryptedBase64, senderPublicKey);
console.log('Decrypted:', decryptedText);
```

### 5. File Encryption

Encrypt files (e.g., images, documents) using a symmetric key.

```typescript
// Generate a random symmetric key (or derive one)
import sodium from 'libsodium-wrappers';
await sodium.ready;
const key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);

// Encrypt
const fileBytes = new Uint8Array([1, 2, 3]); // Your file content
const encryptedFile = await guard.encryptFile(fileBytes, key);

// Decrypt
const decryptedFile = await guard.decryptFile(encryptedFile, key);
```

## Framework Integration

### React / Vue / Angular

1.  **Install**: `npm install chat-secure-guard-js`
2.  **Import**: Use standard ES imports.
3.  **Storage**: Implement `SecureStorageInterface` using `localStorage` or `IndexedDB` (recommended for persistence).

### Node.js
Works out of the box with `libsodium-wrappers`. Use a file-system based storage or environment variables for key persistence if needed.

## Security Notes

- **Storage**: The default `InMemorySecureStorage` does not persist keys across page reloads. For production apps, implement a persistent storage adapter securely.
- **Keys**: Never expose your Private Key.
- **Network**: Only send Encrypted messages and Public Keys over the network.

## License
MIT
