<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

use Neos\Flow\Annotations as Flow;

#[Flow\Scope('singleton')]
class EncryptionService {

    #[Flow\InjectConfiguration(path: 'encryption.base64EncodedKey')]
    protected string $base64EncodedKey = '';

    protected string $key;

    public function initializeObject(): void
    {
        $key = base64_decode($this->base64EncodedKey, true);
        if ($key === false) {
            throw new \RuntimeException('Failed base64-decoding the encryption key provided as setting encryption.base64EncodedKey', 1604935600);
        }
        if ($key !== '' && strlen($key) !== SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES) {
            throw new \RuntimeException(sprintf('The encryption key provided as setting encryption.base64EncodedKey must be %d bytes long. Generate one with ./flow oauth:generateencryptionkey', SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES), 1789145563);
        }
        $this->key = $key;
    }

    public function setKey(string $key): void
    {
        $this->key = $key;
    }

    public function isConfigured(): bool
    {
        return !empty($this->key);
    }

    /**
     * Encrypts the given data using the configured encryption method and returns a string
     * containing the construction name and the base64-encoded nonce and encrypted data.
     *
     * @throws \Exception
     */
    public function encryptAndEncode(string $data): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $encryptedData = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $data,
            $nonce,
            $nonce,
            $this->key
        );

        return 'ChaCha20-Poly1305-IETF$' . base64_encode($nonce) . '$' . base64_encode($encryptedData);
    }

    /**
     * Decrypts the given encoded and encrypted data using the configured encryption method
     * and returns the decrypted data.
     *
     * @throws \SodiumException
     * @see encryptAndEncode()
     */
    public function decodeAndDecrypt(string $encodedAndEncryptedData): string
    {
        [$construction, $encodedNonce, $encodedEncryptedSerializedAccessToken] = explode('$', $encodedAndEncryptedData);
        if ($construction !== 'ChaCha20-Poly1305-IETF') {
            throw new \RuntimeException(sprintf('Failed decrypting serialized access token: unsupported AEAD construction "%s"', $construction), 1604938723);
        }

        $nonce = base64_decode($encodedNonce);
        $decryptedData = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            base64_decode($encodedEncryptedSerializedAccessToken),
            $nonce,
            $nonce,
            $this->key
        );
        // The native Sodium extension signals a wrong key or tampered data by returning false.
        if ($decryptedData === false) {
            throw new \SodiumException('Failed decrypting serialized access token: the key does not match or the data was modified');
        }
        return $decryptedData;
    }

    /**
     * @throws \Exception
     */
    public function generateEncryptionKey(): string
    {
        return sodium_crypto_aead_chacha20poly1305_ietf_keygen();
    }
}
