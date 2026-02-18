import sodium from 'libsodium-wrappers';

export class FileCrypto {
    private sodiumInstance: typeof sodium;

    constructor(sodiumLib: typeof sodium) {
        this.sodiumInstance = sodiumLib;
    }

    /**
     * Encrypts a file (Uint8Array) using symmetric key (SecretBox).
     * Generates a random nonce and prepends it to the file content.
     * Returns: [Nonce (24 bytes)][Encrypted Content]
     */
    async encryptFile(fileBytes: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        const nonce = this.sodiumInstance.randombytes_buf(
            this.sodiumInstance.crypto_secretbox_NONCEBYTES
        );

        const encryptedContent = this.sodiumInstance.crypto_secretbox_easy(
            fileBytes,
            nonce,
            key
        );

        const result = new Uint8Array(nonce.length + encryptedContent.length);
        result.set(nonce);
        result.set(encryptedContent, nonce.length);

        return result;
    }

    /**
     * Decrypts a file (Uint8Array) using symmetric key.
     * Expects: [Nonce (24 bytes)][Encrypted Content]
     */
    async decryptFile(encryptedBytes: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        const nonceLength = this.sodiumInstance.crypto_secretbox_NONCEBYTES;
        if (encryptedBytes.length < nonceLength) {
            throw new Error('Invalid encrypted file format: too short');
        }

        const nonce = encryptedBytes.slice(0, nonceLength);
        const ciphertext = encryptedBytes.slice(nonceLength);

        const decrypted = this.sodiumInstance.crypto_secretbox_open_easy(
            ciphertext,
            nonce,
            key
        );

        return decrypted;
    }
}
