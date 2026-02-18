import { ChatSecureGuard } from '../src/ChatSecureGuard';

async function main() {
    console.log('Initializing ChatSecureGuard...');

    // Using default InMemorySecureStorage
    const guard = await ChatSecureGuard.init();

    console.log('Generating keys...');
    const myPublicKey = await guard.getPublicKey();
    console.log('Public Key retrieved (length):', myPublicKey.length);
    // console.log('Public Key (Base64):', Buffer.from(myPublicKey).toString('base64')); // Buffer is Node only

    // Simulate another user (receiver)
    // In a real app, this key would come from the server
    // For demo, we just encrypt to ourselves
    const receiverPublicKey = myPublicKey;

    console.log('Encrypting message: "Hello Secure World"');
    const message = "Hello Secure World";
    const encrypted = await guard.encrypt(message, receiverPublicKey);
    console.log('Encrypted (Base64):', encrypted);

    console.log('Decrypting message...');
    // We use our own public key as sender because we encrypted to ourselves
    const decrypted = await guard.decrypt(encrypted, myPublicKey);

    console.log('Decrypted:', decrypted);

    if (message === decrypted) {
        console.log('✅ Success! Message encrypted and decrypted correctly.');
    } else {
        console.error('❌ Failed! Message mismatch.');
    }
}

main().catch(console.error);
