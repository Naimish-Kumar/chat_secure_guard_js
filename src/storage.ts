
// Abstract interface for Secure Storage.
export interface SecureStorageInterface {
    write(key: string, value: string): Promise<void>;
    read(key: string): Promise<string | null>;
    delete(key: string): Promise<void>;
}

// In-Memory implementation (default for demo/tests).
// For production use in browser, use IndexedDB wrapper (e.g., localForage)
// For Node.js, implement a filesystem or keychain based solution.
// For React Native, use SecureStore.
export class InMemorySecureStorage implements SecureStorageInterface {
    private store: Map<string, string> = new Map();

    async write(key: string, value: string): Promise<void> {
        this.store.set(key, value);
    }

    async read(key: string): Promise<string | null> {
        return this.store.get(key) || null;
    }

    async delete(key: string): Promise<void> {
        this.store.delete(key);
    }
}
