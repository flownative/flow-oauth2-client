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

use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;

/**
 * A public key which StateVerifier trusts, and the hosts it may sign for, see TargetHostPatterns
 */
#[Flow\Proxy(false)]
final readonly class StateVerificationKey
{
    private function __construct(
        public string $keyId,
        public string $publicKey,
        public TargetHostPatterns $allowedHostPatterns,
    ) {
    }

    /**
     * @param list<string> $allowedHostPatterns
     */
    public static function fromBase64EncodedPublicKey(string $keyId, string $base64EncodedPublicKey, array $allowedHostPatterns): self
    {
        return new self($keyId, self::decodePublicKey($keyId, $base64EncodedPublicKey), TargetHostPatterns::fromArray($allowedHostPatterns));
    }

    /**
     * For a relay which trusts the key with any host name; IP addresses stay refused
     */
    public static function allowingAnyHost(string $keyId, string $base64EncodedPublicKey): self
    {
        return new self($keyId, self::decodePublicKey($keyId, $base64EncodedPublicKey), TargetHostPatterns::anyHost());
    }

    public function allowsTargetHost(string $targetHost): bool
    {
        return $this->allowedHostPatterns->matches($targetHost);
    }

    private static function decodePublicKey(string $keyId, string $base64EncodedPublicKey): string
    {
        $publicKey = base64_decode($base64EncodedPublicKey, true);
        if (!is_string($publicKey) || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidArgumentException(sprintf('The public key for verifying states with key id "%s" must be a base64-encoded Ed25519 public key of %d bytes.', $keyId, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES), 1793862947);
        }
        return $publicKey;
    }
}
