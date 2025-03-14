#!/usr/bin/env -S deno run --allow-read --allow-write

const PHASED = Deno.env.get("PHASED")!;

interface Phased {
  encrypted: string; // Base64 encoded encrypted data
  iv: string; // Base64 encoded initialization vector
  salt: string; // Base64 encoded salt
}

/**
 * Converts a string to Uint8Array using TextEncoder
 */
function strToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts Uint8Array to string using TextDecoder
 */
function uint8ArrayToStr(uint8Array: Uint8Array): string {
  return new TextDecoder().decode(uint8Array);
}

/**
 * Generates a random salt for key derivation
 */
function generateSalt(length: number = 16): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generates a random initialization vector (IV) for AES-GCM
 */
function generateIV(length: number = 12): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Derives a cryptographic key from a private key and salt using PBKDF2
 */
async function deriveKey(
  privateKey: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  // Import the private key as raw key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    strToUint8Array(privateKey),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  // Derive a key using PBKDF2
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000, // High iteration count for security
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a password using a private key
 * @param password The password to encrypt
 * @param privateKey The private key for encryption
 * @returns Object containing the encrypted password, IV, and salt (all base64 encoded)
 */
export async function encryptPassword(
  password: string,
  privateKey: string = PHASED
): Promise<Phased> {
  if (!privateKey) {
    throw new Error("PHASED environment variable is not set");
  }

  // Generate a random salt and IV
  const salt = generateSalt();
  const iv = generateIV();

  // Derive a key from the private key and salt
  const key = await deriveKey(privateKey, salt);

  // Encrypt the password
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    strToUint8Array(password)
  );

  // Convert to base64 for storage or transmission
  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt)),
  };
}

/**
 * Decrypts a password using a private key
 * @param options Object containing the encrypted password, IV, salt, and private key
 * @returns The decrypted password as a string
 */
export async function decryptPassword(
  options: Phased,
  privateKey: string = PHASED
): Promise<string> {
  if (!privateKey) {
    throw new Error("PHASED environment variable is not set");
  }

  const { encrypted, iv, salt } = options;

  // Convert base64 strings back to Uint8Arrays
  const encryptedData = Uint8Array.from(atob(encrypted), (c) =>
    c.charCodeAt(0)
  );
  const ivData = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
  const saltData = Uint8Array.from(atob(salt), (c) => c.charCodeAt(0));

  // Derive the key using the same process as encryption
  const key = await deriveKey(privateKey, saltData);

  // Decrypt the password
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivData,
    },
    key,
    encryptedData
  );

  return uint8ArrayToStr(new Uint8Array(decrypted));
}

/**
 * Verifies if a password matches an encrypted value without revealing the password
 * @param password The password to verify
 * @param encryptedData The encrypted data (from encryptPassword)
 * @param privateKey The private key used for encryption
 * @returns true if the password matches, false otherwise
 */
export async function verifyPassword(
  password: string,
  encryptedData: Phased,
  privateKey: string = PHASED
): Promise<boolean> {
  try {
    const decrypted = await decryptPassword(encryptedData, privateKey);

    // Use constant-time comparison to prevent timing attacks
    // (This is a simple implementation - a more sophisticated one would be better for production)
    if (password.length !== decrypted.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < password.length; i++) {
      result |= password.charCodeAt(i) ^ decrypted.charCodeAt(i);
    }

    return result === 0;
  } catch (_error) {
    // If decryption fails (e.g., wrong private key), return false
    return false;
  }
}

const help = `
Phaser

string (is your password)

phaser(env PHASER is your secret private key)

{ encrypted: string; // Base64 encoded encrypted data
  iv: string; // Base64 encoded initialization vector
  salt: string; // Base64 encoded salt }

USAGE:
  deno run --allow-read --allow-write password-cli.ts [COMMAND] [OPTIONS]
`;

async function main() {
  const [arg] = Deno.args;
  if (!arg) {
    console.log(help);
  }
  if (arg.includes(`"encrypted"`)) {
    const encrypted = JSON.parse(arg);
    console.log(await decryptPassword(encrypted));
  } else {
    console.log(JSON.stringify(await encryptPassword(arg), null, 2));
  }
}

if (import.meta.main) {
  await main();
}
