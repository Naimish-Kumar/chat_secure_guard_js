import sodium from 'libsodium-wrappers';

export interface RatchetSession {
    rootKey: Uint8Array;
    sendChainKey: Uint8Array;
    recvChainKey: Uint8Array;
    myRatchetKey: sodium.KeyPair;
    remoteRatchetKey: Uint8Array | null;
}

export interface EncryptedPacket {
    header_key: Uint8Array;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
}

export class DoubleRatchet {
    private sodiumLib: typeof sodium;

    constructor(sodiumLib: typeof sodium) {
        this.sodiumLib = sodiumLib;
    }

    /**
     * 1. Initialize a new sender session
     */
    initSenderSession(sharedSecret: Uint8Array, remotePublicKey: Uint8Array): RatchetSession {
        const keyPair = this.sodiumLib.crypto_box_keypair();
        const dhOut = this._diffieHellman(keyPair, remotePublicKey);

        const [newRoot, chainSend] = this._kdfRoot(sharedSecret, dhOut);

        return {
            rootKey: newRoot,
            sendChainKey: chainSend,
            recvChainKey: new Uint8Array(32), // Empty initially
            myRatchetKey: keyPair,
            remoteRatchetKey: remotePublicKey
        };
    }

    /**
     * 2. Initialize a new receiver session
     */
    initReceiverSession(sharedSecret: Uint8Array, myRatchetKeyPair: sodium.KeyPair): RatchetSession {
        return {
            rootKey: sharedSecret,
            sendChainKey: new Uint8Array(32),
            recvChainKey: new Uint8Array(32),
            myRatchetKey: myRatchetKeyPair,
            remoteRatchetKey: null
        };
    }

    /**
     * Encrypts a message and advances the sending chain.
     */
    encrypt(session: RatchetSession, message: string): EncryptedPacket {
        // 1. Derive Message Key
        const [newChainKey, messageKey] = this._kdfChain(session.sendChainKey);
        session.sendChainKey = newChainKey;

        // 2. Encrypt Message
        const nonce = this.sodiumLib.randombytes_buf(this.sodiumLib.crypto_secretbox_NONCEBYTES);
        const cipherText = this.sodiumLib.crypto_secretbox_easy(
            message,
            nonce,
            messageKey
        );

        // 3. Return Packet
        return {
            header_key: session.myRatchetKey.publicKey,
            nonce: nonce,
            ciphertext: cipherText
        };
    }

    /**
     * Decrypts a message.
     */
    decrypt(session: RatchetSession, packet: EncryptedPacket): string {
        const headerKey = packet.header_key;
        const nonce = packet.nonce;
        const ciphertext = packet.ciphertext;

        // Ratchet Step if needed
        if (session.remoteRatchetKey === null || !this._bytesEqual(headerKey, session.remoteRatchetKey)) {
            this._ratchetStep(session, headerKey);
            session.remoteRatchetKey = headerKey;
        }

        // 1. Derive Message Key
        const [newChainKey, messageKey] = this._kdfChain(session.recvChainKey);
        session.recvChainKey = newChainKey;

        // 2. Decrypt
        const decrypted = this.sodiumLib.crypto_secretbox_open_easy(
            ciphertext,
            nonce,
            messageKey
        );

        return this.sodiumLib.to_string(decrypted);
    }

    /**
     * Helper: Replicate the 'Box on Zeros' shared secret derivation to match Dart
     */
    private _diffieHellman(myKeyPair: sodium.KeyPair, remotePublicKey: Uint8Array): Uint8Array {
        const subNonce = new Uint8Array(this.sodiumLib.crypto_box_NONCEBYTES); // Zeros
        const zeros = new Uint8Array(32); // Zeros

        const sharedEncrypted = this.sodiumLib.crypto_box_easy(
            zeros,
            subNonce,
            remotePublicKey,
            myKeyPair.privateKey
        );

        // Return first 32 bytes
        return sharedEncrypted.subarray(0, 32);
    }

    private _kdfRoot(rootKey: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
        // Input 0x01 + dhOut
        const input1 = new Uint8Array(1 + dhOut.length);
        input1[0] = 0x01;
        input1.set(dhOut, 1);

        const nextRoot = this.sodiumLib.crypto_generichash(32, input1, rootKey);

        // Input 0x02 + dhOut
        const input2 = new Uint8Array(1 + dhOut.length);
        input2[0] = 0x02;
        input2.set(dhOut, 1);

        const nextChain = this.sodiumLib.crypto_generichash(32, input2, rootKey);

        return [nextRoot, nextChain];
    }

    private _kdfChain(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
        // Msg Key: Input 0x01
        const input1 = new Uint8Array([0x01]);
        const msgKey = this.sodiumLib.crypto_generichash(32, input1, chainKey);

        // Next Chain: Input 0x02
        const input2 = new Uint8Array([0x02]);
        const nextChain = this.sodiumLib.crypto_generichash(32, input2, chainKey);

        return [nextChain, msgKey];
    }

    private _ratchetStep(session: RatchetSession, newRemotePublicKey: Uint8Array) {
        // 1. DH with old Ratchet Key (Receiver Step)
        const dh1 = this._diffieHellman(session.myRatchetKey, newRemotePublicKey);
        const [nextRoot1, rectChain] = this._kdfRoot(session.rootKey, dh1);

        session.rootKey = nextRoot1;
        session.recvChainKey = rectChain;

        // 2. Generate new Ratchet Key
        session.myRatchetKey = this.sodiumLib.crypto_box_keypair();

        // 3. DH with new Ratchet Key
        const dh2 = this._diffieHellman(session.myRatchetKey, newRemotePublicKey);
        const [nextRoot2, sendChain] = this._kdfRoot(session.rootKey, dh2);

        session.rootKey = nextRoot2;
        session.sendChainKey = sendChain;
    }

    private _bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}
