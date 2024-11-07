import { LOCK_TYPES, isSafeToWrite, getPageSize } from '../sqlite-util';
import idbReady from 'safari-14-idb-fix';
import { openDB as openIDB } from 'idb';

function positionToKey(pos, blockSize) {
  // We are forced to round because of floating point error. `pos`
  // should always be divisible by `blockSize`
  return Math.round(pos / blockSize);
}

async function openDb(name) {
  await idbReady();

  const idb = await openIDB(name, 2, {
    upgrade: (db) => {
      if (!db.objectStoreNames.contains('data')) {
        db.createObjectStore('data');
      }
    },
    terminated: () => {},
    blocked: (_currentVersion, _blockedVersion, event) => {
      console.error('blocked', event);
    },
  });

  idb.onversionchange = () => {
    idb.close();
  };

  idb.onerror = (e) => {
    console.error('error', e);
  };

  return idb;
}

const CRYPTO_ALGORITHM = { name: 'AES-GCM', length: 256 };
const IV_LENGTH = 12;
const ENCRYPTION_MARKER = new Uint8Array([0xde, 0xad, 0xbe, 0xef]); // Marker to identify encrypted data

function generateKey(password) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(password);

  return crypto.subtle
    .importKey('raw', keyData, { name: 'PBKDF2' }, false, [
      'deriveBits',
      'deriveKey',
    ])
    .then((keyMaterial) =>
      crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: keyData,
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        CRYPTO_ALGORITHM,
        false,
        ['encrypt', 'decrypt']
      )
    );
}

function isEncrypted(data) {
  if (!data || !(data instanceof ArrayBuffer)) return false;

  const marker = new Uint8Array(data, 0, ENCRYPTION_MARKER.length);
  return marker.every((byte, i) => byte === ENCRYPTION_MARKER[i]);
}

async function encryptData(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  // Combine marker, IV, and encrypted data
  const result = new Uint8Array(
    ENCRYPTION_MARKER.length + IV_LENGTH + encryptedData.byteLength
  );
  result.set(ENCRYPTION_MARKER, 0);
  result.set(iv, ENCRYPTION_MARKER.length);
  result.set(
    new Uint8Array(encryptedData),
    ENCRYPTION_MARKER.length + IV_LENGTH
  );

  return result.buffer;
}

async function decryptData(key, encryptedBuffer) {
  if (!encryptedBuffer) return encryptedBuffer;

  const data = new Uint8Array(encryptedBuffer);
  const iv = data.slice(
    ENCRYPTION_MARKER.length,
    ENCRYPTION_MARKER.length + IV_LENGTH
  );
  const encryptedContent = data.slice(ENCRYPTION_MARKER.length + IV_LENGTH);

  const result = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encryptedContent
  );

  return result;
}

// Using a separate class makes it easier to follow the code, and
// importantly it removes any reliance on internal state in
// `FileOpsFallback`. That would be problematic since these method
// happen async; the args to `write` must be closed over so they don't
// change
class Persistance {
  constructor(dbName, onFallbackFailure, encryptionPassword = null) {
    this.dbName = dbName;
    this._openDbPromise = null;
    this.hasAlertedFailure = false;
    this.onFallbackFailure = onFallbackFailure;
    this.encryptionPassword = encryptionPassword;
    this.cryptoKey = null;
  }

  async migrateToEncrypted() {
    if (!this.cryptoKey) {
      console.warn('No crypto key available for migration');
      return;
    }

    let db = await this.getDb(this.dbName);
    let trans = db.transaction('data', 'readwrite');
    let store = trans.objectStore('data');

    // Get all data
    let [allValues, allKeys] = await Promise.all([
      store.getAll(),
      store.getAllKeys(),
    ]);
    let migrationWrites = [];

    // Process each value
    for (let i = 0; i < allValues.length; i++) {
      let value = allValues[i];
      let key = allKeys[i];

      // Only encrypt if not already encrypted
      if (!isEncrypted(value) && !value.size) {
        try {
          const encryptedValue = await encryptData(this.cryptoKey, value);
          migrationWrites.push({ key, value: encryptedValue });
        } catch (err) {
          console.error(
            `Failed to encrypt data for key ${key}: ${err.message}`
          );
        }
      }
    }

    trans = db.transaction('data', 'readwrite');
    store = trans.objectStore('data');
    // Write all encrypted values back to the database
    if (migrationWrites.length > 0) {
      console.log(
        `Migrating ${migrationWrites.length} items to encrypted storage`
      );
      const promises = migrationWrites.map((write) =>
        store.put(write.value, write.key)
      );
      await Promise.all([...promises, trans.done]);
    }

    return migrationWrites.length;
  }

  async generateCryptoKey() {
    if (!this.encryptionPassword) return;

    this.cryptoKey = await generateKey(this.encryptionPassword);
  }

  getDb() {
    if (this._openDbPromise) {
      return this._openDbPromise;
    }

    this._openDbPromise = openDb(this.dbName);
    return this._openDbPromise;
  }

  closeDb() {
    if (this._openDbPromise) {
      this._openDbPromise.then((db) => db.close());
      this._openDbPromise = null;
    }
  }

  // Both `readAll` and `write` rely on IndexedDB transactional
  // semantics to work, otherwise we'd have to coordinate them. If
  // there are pending writes, the `readonly` transaction in `readAll`
  // will block until they are all flushed out. If `write` is called
  // multiple times, `readwrite` transactions can only run one at a
  // time so it will naturally apply the writes sequentially (and
  // atomically)

  async readAll() {
    if (this.encryptionPassword && !this.cryptoKey) {
      await this.generateCryptoKey();
      await this.migrateToEncrypted();
    }

    let db = await this.getDb(this.dbName);

    let trans = db.transaction('data', 'readonly');
    let store = trans.objectStore('data');

    let [allValues, allKeys] = await Promise.all([
      store.getAll(),
      store.getAllKeys(),
    ]);

    let blocks = new Map();

    for (let i = 0; i < allValues.length; i++) {
      let value = allValues[i];
      let key = allKeys[i];

      if (this.cryptoKey && key > -1) {
        try {
          value = await decryptData(this.cryptoKey, value);
        } catch (err) {
          console.error('Failed to decrypt data: ' + err.message);
        }
      }
      blocks.set(key, value);
    }

    return blocks;
  }

  async write(writes, cachedFirstBlock, hasLocked) {
    // Encrypt the data if needed
    const processedWrites = await Promise.all(
      writes.map(async (write) => {
        if (this.cryptoKey) {
          if (write.value.size) {
            return {
              key: write.key,
              value: write.value,
            };
          }
          try {
            return {
              key: write.key,
              value: await encryptData(this.cryptoKey, write.value),
            };
          } catch (err) {
            console.error('Failed to encrypt data: ' + err.message);
            return {
              key: write.key,
              value: write.value,
            };
          }
        } else {
          return write;
        }
      })
    );

    let db = await this.getDb(this.dbName);

    // We need grab a readwrite lock on the db, and then read to check
    // to make sure we can write to it
    let trans = db.transaction('data', 'readwrite');
    let store = trans.store;

    let req = await store.get(0);

    const decryptReq = this.cryptoKey
      ? await decryptData(this.cryptoKey, req)
      : req;

    if (hasLocked) {
      if (!isSafeToWrite(decryptReq, cachedFirstBlock)) {
        if (this.onFallbackFailure && !this.hasAlertedFailure) {
          this.hasAlertedFailure = true;
          this.onFallbackFailure();
        }
        throw new Error('Fallback mode unable to write file changes');
      }
    }

    // Flush all the writes
    trans = db.transaction('data', 'readwrite');
    store = trans.store;
    const promises = processedWrites.map((processedWrite) =>
      store.put(processedWrite.value, processedWrite.key)
    );

    await Promise.all([...promises, trans.done]);
  }
}

export class FileOpsFallback {
  constructor(filename, onFallbackFailure, passwordMap) {
    this.filename = filename;
    this.dbName = this.filename.replace(/\//g, '-');
    this.cachedFirstBlock = null;
    this.writeQueue = null;
    this.blocks = new Map();
    this.lockType = 0;
    this.transferBlockOwnership = false;
    const password = passwordMap?.get(this.filename) ?? null;

    this.persistance = new Persistance(
      this.dbName,
      onFallbackFailure,
      password
    );
  }

  async readIfFallback() {
    this.transferBlockOwnership = true;
    this.blocks = await this.persistance.readAll();

    return this.readMeta();
  }

  lock(lockType) {
    // Locks always succeed here. Essentially we're only working
    // locally (we can't see any writes from anybody else) and we just
    // want to track the lock so we know when it downgrades from write
    // to read
    this.cachedFirstBlock = this.blocks.get(0);
    this.lockType = lockType;
    return true;
  }

  unlock(lockType) {
    if (this.lockType > LOCK_TYPES.SHARED && lockType === LOCK_TYPES.SHARED) {
      // Within a write lock, we delay all writes until the end of the
      // lock. We probably don't have to do this since we already
      // delay writes until an `fsync`, however this is an extra
      // measure to make sure we are writing everything atomically
      this.flush();
    }
    this.lockType = lockType;
    return true;
  }

  delete() {
    let req = globalThis.indexedDB.deleteDatabase(this.dbName);
    req.onerror = () => {
      console.warn(`Deleting ${this.filename} database failed`);
    };
    req.onsuccess = () => {};
  }

  open() {
    this.writeQueue = [];
    this.lockType = 0;
  }

  close() {
    this.flush();

    if (this.transferBlockOwnership) {
      this.transferBlockOwnership = false;
    } else {
      this.blocks = new Map();
    }

    this.persistance.closeDb();
  }

  readMeta() {
    let metaBlock = this.blocks.get(-1);
    if (metaBlock) {
      let block = this.blocks.get(0);

      return {
        size: metaBlock.size,
        blockSize: getPageSize(new Uint8Array(block)),
      };
    }
    return null;
  }

  writeMeta(meta) {
    this.blocks.set(-1, meta);
    this.queueWrite(-1, meta);
  }

  readBlocks(positions, blockSize) {
    let res = [];
    for (let pos of positions) {
      res.push({
        pos,
        data: this.blocks.get(positionToKey(pos, blockSize)),
      });
    }
    return res;
  }

  writeBlocks(writes, blockSize) {
    for (let write of writes) {
      let key = positionToKey(write.pos, blockSize);
      this.blocks.set(key, write.data);
      this.queueWrite(key, write.data);
    }

    // No write lock; flush them out immediately
    if (this.lockType <= LOCK_TYPES.SHARED) {
      this.flush();
    }
  }

  queueWrite(key, value) {
    this.writeQueue.push({ key, value });
  }

  flush() {
    if (this.writeQueue.length > 0) {
      this.persistance.write(
        this.writeQueue,
        this.cachedFirstBlock,
        this.lockType > LOCK_TYPES.SHARED
      );
      this.writeQueue = [];
    }
    this.cachedFirstBlock = null;
  }
}
