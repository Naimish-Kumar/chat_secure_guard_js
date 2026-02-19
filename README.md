
## Overview
`chat-secure-guard-js` is a secure end-to-end encryption library for **Web**, **React Native**, and **Node.js**.

It brings the **Double Ratchet Algorithm** (WhatsApp & Signal protocol) to JS/TS applications, enabling perfect forward secrecy and secure messaging.

This package is fully compatible with the Flutter `chat_secure_guard` library, allowing you to build cross-platform secure chat apps.

## Features
- 🔄 **Double Ratchet Algorithm**: Military-grade security with per-message key rotation.
- 📱 **React Native Support**: Works out-of-the-box (requires polyfill).
- 🌐 **Web Support**: Use in React, Vue, Angular, or vanilla JS.
- 🔑 **Secure Key Management**: Automated ED25519 key generation.
- 📂 **File Encryption**: Securely encrypt large files (images/videos).

## Installation

```bash
npm install chat-secure-guard-js
```

> **Note:** This package is powered by `libsodium-wrappers` which is installed automatically.

## React Native Setup 📱

React Native requires a polyfill for random bytes and a secure storage adapter.

1.  **Install Dependencies**:
    ```bash
    npm install react-native-get-random-values expo-secure-store
    ```

2.  **Add Polyfill**: In your `index.js` (at the top):
    ```javascript
    import 'react-native-get-random-values';
    ```

3.  **Implement Storage Adapter**:
    Create a `RNSecureStorage` class implementing `SecureStorageInterface` using `expo-secure-store` (see `examples/ReactNativeAdapter.ts` for full code).

## Web Usage 🌐

### 1. Initialization
Initialize once at app start.

```typescript
import { ChatSecureGuard } from 'chat-secure-guard-js';

// Pass your storage adapter (e.g. localStorage wrapper)
const guard = await ChatSecureGuard.init(new MyLocalStorageAdapter());
```

### 2. Double Ratchet Encryption (WhatsApp Style) 🚀

This is the recommended way to secure chats. Keys rotate automatically.

#### Setup Sessions
Use a shared secret (derived via X3DH or key exchange server).

```typescript
import { DoubleRatchet } from 'chat-secure-guard-js';

// 1. Get Sodium Instance
const sodium = guard.sodium;
const ratchet = new DoubleRatchet(sodium);

// 2. Initialize Session (Alice - Sender)
const senderSession = ratchet.initSenderSession(sharedSecret, bobPublicKey);

// 3. Initialize Session (Bob - Receiver)
const receiverSession = ratchet.initReceiverSession(sharedSecret, bobPreKey);
```

#### Send Message
```typescript
const packet = ratchet.encrypt(senderSession, "Hello Secure Web!");
// packet contains: { header_key, nonce, ciphertext }
// Send this object to your server.
```

#### Receive Message
```typescript
// Bob receives 'packet'
const msg = ratchet.decrypt(receiverSession, packet);
console.log(msg); // "Hello Secure Web!"
```

### 3. File Encryption
Encrypt files before uploading (e.g., to S3/Firebase).

```typescript
const fileBytes = new Uint8Array([1, 2, 3]); // Your file data
const key = sodium.randombytes_buf(32);

// Encrypt
const encrypted = await guard.encryptFile(fileBytes, key);

// Decrypt
const original = await guard.decryptFile(encrypted, key);
```

## API Reference

### `ChatSecureGuard`
- `init(storage)`: Initialize library (required).
- `getPublicKey()`: Returns user's public identity key.
- `encrypt(msg, pubKey)`: One-shot encryption (legacy).
- `decrypt(msg, pubKey)`: One-shot decryption (legacy).
- `encryptFile(bytes, key)`: Symmetric file encryption.
- `decryptFile(bytes, key)`: Symmetric file decryption.

### `DoubleRatchet`
- `initSenderSession(secret, remoteKey)`: Start a session as initiator.
- `initReceiverSession(secret, localPair)`: Start a session as responder.
- `encrypt(session, msg)`: Encrypt next message & rotate keys.
- `decrypt(session, packet)`: Decrypt received message & rotate keys.

## License
MIT
