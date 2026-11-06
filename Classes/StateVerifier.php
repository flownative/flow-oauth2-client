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
 * Verifies a SignedState with the public keys of the installations which may send returns through a relay
 *
 * It needs neither Flow's persistence nor a cache, so that a relay can use it on its own. A state older than the state cache of the
 * client is refused, so that a leaked state can't be replayed later.
 */
#[Flow\Proxy(false)]
final readonly class StateVerifier
{
    public const int DEFAULT_MAXIMUM_AGE = 3600;
    public const int DEFAULT_CLOCK_SKEW = 60;

    /**
     * @var array<string, StateVerificationKey>
     */
    private array $keys;

    /**
     * @param list<StateVerificationKey> $keys
     * @param int $maximumAge Seconds; keep it at the lifetime of the client's state cache
     * @param int $clockSkew Seconds the clocks of client and relay may differ
     */
    public function __construct(
        array $keys,
        private int $maximumAge = self::DEFAULT_MAXIMUM_AGE,
        private int $clockSkew = self::DEFAULT_CLOCK_SKEW,
    ) {
        $keysById = [];
        foreach ($keys as $key) {
            if (isset($keysById[$key->keyId])) {
                throw new InvalidArgumentException(sprintf('The key id "%s" is given more than once.', $key->keyId), 1793863401);
            }
            $keysById[$key->keyId] = $key;
        }
        $this->keys = $keysById;
    }

    /**
     * @throws InvalidSignedStateException
     */
    public function verify(string $state): SignedState
    {
        $signedState = SignedState::fromString($state);
        $key = $this->keys[$signedState->keyId] ?? null;
        if ($key === null) {
            throw new InvalidSignedStateException(sprintf('The state was signed with the unknown key id "%s".', $signedState->keyId), 1793862949);
        }
        if (!sodium_crypto_sign_verify_detached($signedState->signature, $signedState->getSignedMessage(), $key->publicKey)) {
            throw new InvalidSignedStateException(sprintf('The signature of the state does not match key id "%s".', $signedState->keyId), 1793862950);
        }
        if (!$key->allowsTargetHost($signedState->targetHost)) {
            throw new InvalidSignedStateException(sprintf('Key id "%s" may not sign states for host "%s".', $signedState->keyId, $signedState->targetHost), 1793862951);
        }
        $now = time();
        if ($signedState->issuedAt > $now + $this->clockSkew) {
            throw new InvalidSignedStateException('The state was issued in the future.', 1793863402);
        }
        if ($signedState->issuedAt < $now - $this->maximumAge - $this->clockSkew) {
            throw new InvalidSignedStateException('The state has expired.', 1793863403);
        }
        return $signedState;
    }
}
