import sodium from 'libsodium-wrappers';

export class EncryptionService {
    private sodiumInstance: typeof sodium;

    constructor(sodiumLib: typeof sodium) {
        this.sodiumInstance = sodiumLib;
    }

    /**
     * Encrypts a message using a receiver's public key (Box).
     * Generates a random nonce and returns it prepended to the ciphertext.
     * Format: [Nonce (24 bytes)][Ciphertext]
     */
    encryptMessage(
        message: string,
        receiverPublicKey: Uint8Array,
        senderPrivateKey: Uint8Array
    ): string {
        const nonce = this.sodiumInstance.randombytes_buf(
            this.sodiumInstance.crypto_box_NONCEBYTES
        );
        const messageBytes = this.sodiumInstance.from_string(message);

        const encrypted = this.sodiumInstance.crypto_box_easy(
            messageBytes,
            nonce,
            receiverPublicKey,
            senderPrivateKey
        );

        // Combine nonce + encrypted
        const combined = new Uint8Array(nonce.length + encrypted.length);
        combined.set(nonce);
        combined.set(encrypted, nonce.length);

        // Return as base64 string
        return this.sodiumInstance.to_base64(
            combined,
            this.sodiumInstance.base64_variants.ORIGINAL
        );
    }

    /**
     * Decrypts a message using the sender's public key.
     * Expects base64 encoded string containing [Nonce][Ciphertext].
     */
    decryptMessage(
        encryptedMessageBase64: string,
        senderPublicKey: Uint8Array,
        receiverPrivateKey: Uint8Array
    ): string {
        const encryptedBytes = this.sodiumInstance.from_base64(
            encryptedMessageBase64,
            this.sodiumInstance.base64_variants.ORIGINAL
        );

        const nonceLength = this.sodiumInstance.crypto_box_NONCEBYTES;
        if (encryptedBytes.length < nonceLength) {
            throw new Error('Invalid encrypted message: too short');
        }

        const nonce = encryptedBytes.slice(0, nonceLength);
        const ciphertext = encryptedBytes.slice(nonceLength);

        const decrypted = this.sodiumInstance.crypto_box_open_easy(
            ciphertext,
            nonce,
            senderPublicKey,
            receiverPrivateKey
        );

        return this.sodiumInstance.to_string(decrypted);
    }
}
