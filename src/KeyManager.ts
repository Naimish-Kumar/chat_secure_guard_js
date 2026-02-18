import sodium from 'libsodium-wrappers';
import { SecureStorageInterface } from './storage';

export class KeyManager {
    private sodiumInstance: typeof sodium;
    private storage: SecureStorageInterface;
    private cachedPrivateKey?: Uint8Array;
    private cachedPublicKey?: Uint8Array;

    constructor(sodiumLib: typeof sodium, storage: SecureStorageInterface) {
        this.sodiumInstance = sodiumLib;
        this.storage = storage;
    }

    /**
     * Generates a new key pair and stores it securely.
     * If keys already exist, this will OVERWRITE them.
     */
    async generateKeyPair(): Promise<void> {
        const keyPair = this.sodiumInstance.crypto_box_keypair();

        // Cache in memory for fast access
        this.cachedPrivateKey = keyPair.privateKey;
        this.cachedPublicKey = keyPair.publicKey;

        // Convert to Base64 for storage
        const pubKeyBase64 = this.sodiumInstance.to_base64(
            keyPair.publicKey,
            this.sodiumInstance.base64_variants.ORIGINAL
        );
        const privKeyBase64 = this.sodiumInstance.to_base64(
            keyPair.privateKey,
            this.sodiumInstance.base64_variants.ORIGINAL
        );

        // Write to secure storage
        await this.storage.write('public_key', pubKeyBase64);
        await this.storage.write('private_key', privKeyBase64);
    }

    /**
     * Retrieves the Private Key. Loads from storage if not cached.
     */
    async getPrivateKey(): Promise<Uint8Array> {
        if (this.cachedPrivateKey) return this.cachedPrivateKey;

        await this.loadKeys();
        if (!this.cachedPrivateKey) throw new Error('Private key not found. Call generateKeyPair() first.');
        return this.cachedPrivateKey;
    }

    /**
     * Retrieves the Public Key. Loads from storage if not cached.
     */
    async getPublicKey(): Promise<Uint8Array> {
        if (this.cachedPublicKey) return this.cachedPublicKey;

        await this.loadKeys();
        if (!this.cachedPublicKey) throw new Error('Public key not found. Call generateKeyPair() first.');
        return this.cachedPublicKey;
    }

    /**
     * Check if keys exist in memory or storage.
     */
    async hasKeys(): Promise<boolean> {
        if (this.cachedPrivateKey && this.cachedPublicKey) return true;

        // Try to load
        await this.loadKeys();
        return !!(this.cachedPrivateKey && this.cachedPublicKey);
    }

    private async loadKeys(): Promise<void> {
        const privKeyBase64 = await this.storage.read('private_key');
        const pubKeyBase64 = await this.storage.read('public_key');

        if (privKeyBase64) {
            this.cachedPrivateKey = this.sodiumInstance.from_base64(
                privKeyBase64,
                this.sodiumInstance.base64_variants.ORIGINAL
            );
        }

        if (pubKeyBase64) {
            this.cachedPublicKey = this.sodiumInstance.from_base64(
                pubKeyBase64,
                this.sodiumInstance.base64_variants.ORIGINAL
            );
        }
    }
}
