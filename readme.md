# phaser

A library for securely encrypting and decrypting passwords using a private key

* Uses AES-GCM encryption, which provides both confidentiality and data integrity
* Implements PBKDF2 key derivation with 100,000 iterations to protect against brute force attacks
* Generates random salt for each encryption to prevent rainbow table attacks
* Uses initialization vectors (IV) to ensure different ciphertexts even for identical passwords
* Includes a constant-time comparison function to prevent timing attacks

## Installation

```bash
# to deno project
deno add jsr/@fbehrens/phaser

#locally to zshrc
git clone https://github.com/fbehrens/phaser.git
cd phaser
echo -e "phaser() {\n    deno run --allow-env `pwd`/src/phaser.ts \"\$1\"\n}" >> ~/.zshrc

# .zshrc
phaser() {
    deno run --allow-env /Users/foo/Documents/Github/src/phaser.ts "$1"
}
```
