<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Closure;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use SodiumException;
use Throwable;

/**
 * Signs the target host into the state of an authorization, see SignedState
 *
 * Each installation which shares a relay gets its own key pair. The relay only knows the public keys, so it can't sign a state itself.
 * The signer refuses hosts outside of its patterns, and hosts its optional check doesn't know, because a host taken from a request
 * header is chosen by whoever sends it.
 */
#[Flow\Proxy(false)]
final readonly class StateSigner
{
    private function __construct(
        public string $keyId,
        #[\SensitiveParameter]
        private string $secretKey,
        public TargetHostPatterns $allowedHostPatterns,
        private ?Closure $isKnownTargetHost,
    ) {
    }

    /**
     * @param string $base64EncodedSecretKey An Ed25519 secret key of 64 bytes, for example generated with ./flow oauth:generatestatesigningkey
     * @param list<string> $allowedHostPatterns The hosts of the tenants this installation knows, see TargetHostPatterns
     * @param (Closure(string): bool)|null $isKnownTargetHost Tells whether a host matching the patterns belongs to a known tenant; receives the host in lower case, with the port if it is not the default one, such as "acme.cell-1.example.com:8443"
     */
    public static function fromBase64EncodedSecretKey(string $keyId, #[\SensitiveParameter] string $base64EncodedSecretKey, array $allowedHostPatterns, ?Closure $isKnownTargetHost = null): self
    {
        $secretKey = base64_decode($base64EncodedSecretKey, true);
        if (!is_string($secretKey) || strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidArgumentException(sprintf('The secret key for signing states with key id "%s" must be a base64-encoded Ed25519 secret key of %d bytes.', $keyId, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES), 1793862944);
        }
        if (preg_match(SignedState::KEY_ID_PATTERN, $keyId) !== 1) {
            throw new InvalidArgumentException(sprintf('The key id "%s" for signing states must have 1 to 64 letters, digits, "_" or "-".', $keyId), 1793862945);
        }
        return new self($keyId, $secretKey, TargetHostPatterns::fromArray($allowedHostPatterns), $isKnownTargetHost);
    }

    /**
     * @return array{secretKey: string, publicKey: string} Both base64-encoded
     * @throws SodiumException
     */
    public static function generateKeyPair(): array
    {
        $keyPair = sodium_crypto_sign_keypair();
        return [
            'secretKey' => base64_encode(sodium_crypto_sign_secretkey($keyPair)),
            'publicKey' => base64_encode(sodium_crypto_sign_publickey($keyPair)),
        ];
    }

    /**
     * @param string $targetHost The host to which a relay forwards the return, with a port if it is not the default one
     * @throws TargetHostNotAllowedException
     */
    public function sign(string $targetHost): SignedState
    {
        $targetHost = strtolower($targetHost);
        if (!SignedState::isValidTargetHost($targetHost)) {
            throw new TargetHostNotAllowedException(sprintf('Could not sign a state for the malformed target host "%s".', $targetHost), 1793950379);
        }
        if (!$this->allowedHostPatterns->matches($targetHost)) {
            throw new TargetHostNotAllowedException(sprintf('Key id "%s" may not sign states for host "%s".', $this->keyId, $targetHost), 1793863400);
        }
        try {
            $isKnownTargetHost = $this->isKnownTargetHost === null || ($this->isKnownTargetHost)($targetHost) === true;
        } catch (Throwable $exception) {
            throw new TargetHostNotAllowedException(sprintf('Key id "%s" may not sign states for host "%s", because the check for a known tenant failed: %s', $this->keyId, $targetHost, $exception->getMessage()), 1793950325, $exception);
        }
        if (!$isKnownTargetHost) {
            throw new TargetHostNotAllowedException(sprintf('Key id "%s" may not sign states for host "%s", because it belongs to no known tenant.', $this->keyId, $targetHost), 1793949981);
        }
        $issuedAt = time();
        $random = bin2hex(random_bytes(16));
        try {
            $signature = sodium_crypto_sign_detached(SignedState::renderSignedMessage($this->keyId, $targetHost, $issuedAt, $random), $this->secretKey);
            return SignedState::create($this->keyId, $targetHost, $issuedAt, $random, $signature);
        } catch (SodiumException|InvalidSignedStateException $exception) {
            throw new InvalidArgumentException(sprintf('Could not sign a state for target host "%s": %s', $targetHost, $exception->getMessage()), 1793862946, $exception);
        }
    }

    /**
     * @return array{keyId: string, allowedHostPatterns: TargetHostPatterns}
     */
    public function __debugInfo(): array
    {
        return ['keyId' => $this->keyId, 'allowedHostPatterns' => $this->allowedHostPatterns];
    }
}
