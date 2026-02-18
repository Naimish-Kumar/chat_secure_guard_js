import sodium from 'libsodium-wrappers';

import { KeyManager } from './KeyManager';
import { EncryptionService } from './EncryptionService';
import { FileCrypto } from './FileCrypto';
import { SecureStorageInterface, InMemorySecureStorage } from './storage';

export class ChatSecureGuard {
    private sodiumInstance: typeof sodium;
    private keyManager: KeyManager;
    private encryptionService: EncryptionService;
    private fileCrypto: FileCrypto;

    private constructor(sodiumLib: typeof sodium, storage: SecureStorageInterface) {
        this.sodiumInstance = sodiumLib;
        this.keyManager = new KeyManager(sodiumLib, storage);
        this.encryptionService = new EncryptionService(sodiumLib);
        this.fileCrypto = new FileCrypto(sodiumLib);
    }

    /**
     * Initializes the ChatSecureGuard instance with sodium library ready.
     * @param storage Optional custom implementation of SecureStorageInterface.
     *                Defaults to InMemorySecureStorage if not provided.
     */
    static async init(storage?: SecureStorageInterface): Promise<ChatSecureGuard> {
        await sodium.ready;
        const instance = new ChatSecureGuard(sodium, storage || new InMemorySecureStorage());
        await instance.keyManager.generateKeyPair(); // Ensure keys exist or generate new ones? 
        // Wait, the Dart implementation generates keys IF they don't exist.
        // The KeyManager logic handles checking. 
        // The dart init() calls _keyManager.generateKeyPair() if needed.
        // Let's mirror that logic here.
        if (!await instance.keyManager.hasKeys()) {
            await instance.keyManager.generateKeyPair();
        }
        return instance;
    }

    /**
     * Get the public key as a Uint8Array.
     */
    async getPublicKey(): Promise<Uint8Array> {
        return this.keyManager.getPublicKey();
    }

    /**
     * Encrypt a message using the recipient's public key.
     * @param message The plaintext message string.
     * @param receiverPublicKey The recipient's public key (Uint8Array).
     */
    async encrypt(message: string, receiverPublicKey: Uint8Array): Promise<string> {
        const senderPrivateKey = await this.keyManager.getPrivateKey();
        return this.encryptionService.encryptMessage(
            message,
            receiverPublicKey,
            senderPrivateKey
        );
    }

    /**
     * Decrypt a message using the sender's public key.
     * @param encryptedMessageBase64 The base64 encoded encrypted message.
     * @param senderPublicKey The sender's public key (Uint8Array).
     */
    async decrypt(encryptedMessageBase64: string, senderPublicKey: Uint8Array): Promise<string> {
        const receiverPrivateKey = await this.keyManager.getPrivateKey();
        return this.encryptionService.decryptMessage(
            encryptedMessageBase64,
            senderPublicKey,
            receiverPrivateKey
        );
    }

    /**
     * Encrypt a file (Uint8Array) using a symmetric key.
     */
    async encryptFile(fileBytes: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        return this.fileCrypto.encryptFile(fileBytes, key);
    }

    /**
     * Decrypt a file (Uint8Array) using a symmetric key.
     */
    async decryptFile(encryptedBytes: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        return this.fileCrypto.decryptFile(encryptedBytes, key);
    }
}

// Export for easier import
export { SecureStorageInterface, InMemorySecureStorage };
