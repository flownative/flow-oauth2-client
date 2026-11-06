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

use Neos\Flow\Annotations as Flow;
use SodiumException;

/**
 * An OAuth state which names the host the authorization belongs to, signed with Ed25519
 *
 * A relay which receives the returns of all hosts reads the target host from the state and forwards the browser there, after
 * StateVerifier checked the signature. Parsing alone proves nothing: only a verified state may decide where a browser is sent.
 *
 * Format: "v1.<key id>.<base64url target host>.<issued at>.<random>.<base64url signature>", the issue time in Unix seconds. The
 * signature covers "flownative-oauth2-state." followed by everything before its dot, so that it can't pass for a signature of
 * another protocol.
 */
#[Flow\Proxy(false)]
final readonly class SignedState
{
    public const int MAXIMUM_LENGTH = 1024;

    private const string SIGNATURE_CONTEXT = 'flownative-oauth2-state';
    private const string VERSION = 'v1';
    public const string KEY_ID_PATTERN = '/^[A-Za-z0-9_-]{1,64}\z/';
    private const string TARGET_HOST_PATTERN = '/^(?=.{1,261}\z)[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?\z/';
    private const string ISSUED_AT_PATTERN = '/^(0|[1-9][0-9]{0,11})\z/';
    private const string RANDOM_PATTERN = '/^[a-f0-9]{32}\z/';

    private function __construct(
        public string $keyId,
        public string $targetHost, # host name in lower case, with a port if it is not the default one
        public int $issuedAt, # Unix seconds
        public string $random,
        public string $signature, # binary, 64 bytes
    ) {
    }

    /**
     * @throws InvalidSignedStateException
     */
    public static function fromString(string $state): self
    {
        if (strlen($state) > self::MAXIMUM_LENGTH) {
            throw new InvalidSignedStateException('The signed state is too long.', 1793862937);
        }
        $segments = explode('.', $state);
        if (count($segments) !== 6 || $segments[0] !== self::VERSION) {
            throw new InvalidSignedStateException('The state is not a signed state of a known version.', 1793862938);
        }
        [, $keyId, $encodedTargetHost, $encodedIssuedAt, $random, $encodedSignature] = $segments;
        if (preg_match(self::ISSUED_AT_PATTERN, $encodedIssuedAt) !== 1) {
            throw new InvalidSignedStateException('The issue time of the signed state is malformed.', 1793863398);
        }
        try {
            $targetHost = sodium_base642bin($encodedTargetHost, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $signature = sodium_base642bin($encodedSignature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (SodiumException) {
            throw new InvalidSignedStateException('The signed state is not properly encoded.', 1793862939);
        }
        return self::create($keyId, $targetHost, (int)$encodedIssuedAt, $random, $signature);
    }

    /**
     * @throws InvalidSignedStateException
     */
    public static function create(string $keyId, string $targetHost, int $issuedAt, string $random, string $signature): self
    {
        if (preg_match(self::KEY_ID_PATTERN, $keyId) !== 1) {
            throw new InvalidSignedStateException('The key id of the signed state is malformed.', 1793862940);
        }
        if (!self::isValidTargetHost($targetHost)) {
            throw new InvalidSignedStateException('The target host of the signed state is malformed.', 1793862941);
        }
        if ($issuedAt < 0) {
            throw new InvalidSignedStateException('The issue time of the signed state is negative.', 1793863399);
        }
        if (preg_match(self::RANDOM_PATTERN, $random) !== 1) {
            throw new InvalidSignedStateException('The random part of the signed state is malformed.', 1793862942);
        }
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new InvalidSignedStateException('The signature of the signed state has the wrong length.', 1793862943);
        }
        return new self($keyId, $targetHost, $issuedAt, $random, $signature);
    }

    public static function looksSigned(string $state): bool
    {
        return str_starts_with($state, self::VERSION . '.');
    }

    /**
     * A host name in lower case, with a port up to 65535 if it is not the default one
     */
    public static function isValidTargetHost(string $targetHost): bool
    {
        if (preg_match(self::TARGET_HOST_PATTERN, $targetHost, $matches) !== 1) {
            return false;
        }
        return !isset($matches[2]) || (int)substr($matches[2], 1) <= 65535;
    }

    public static function renderSignedMessage(string $keyId, string $targetHost, int $issuedAt, string $random): string
    {
        return self::SIGNATURE_CONTEXT . '.' . self::renderUnsignedState($keyId, $targetHost, $issuedAt, $random);
    }

    public function getSignedMessage(): string
    {
        return self::renderSignedMessage($this->keyId, $this->targetHost, $this->issuedAt, $this->random);
    }

    public function __toString(): string
    {
        return self::renderUnsignedState($this->keyId, $this->targetHost, $this->issuedAt, $this->random) . '.' . sodium_bin2base64($this->signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    private static function renderUnsignedState(string $keyId, string $targetHost, int $issuedAt, string $random): string
    {
        return implode('.', [self::VERSION, $keyId, sodium_bin2base64($targetHost, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING), (string)$issuedAt, $random]);
    }
}
