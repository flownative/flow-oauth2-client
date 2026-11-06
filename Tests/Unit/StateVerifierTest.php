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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class StateVerifierTest extends TestCase
{
    private array $keyPair;

    protected function setUp(): void
    {
        $this->keyPair = StateSigner::generateKeyPair();
    }

    #[Test]
    public function verifyReturnsTheSignedTargetHost(): void
    {
        $signedState = $this->createSigner('cell-1')->sign('Acme.Example.com:8443');

        $verifiedState = $this->createVerifier('cell-1')->verify((string)$signedState);

        self::assertSame('acme.example.com:8443', $verifiedState->targetHost);
        self::assertSame('cell-1', $verifiedState->keyId);
        self::assertSame($signedState->random, $verifiedState->random);
    }

    #[Test]
    public function signedStatesUseOnlyCharactersAllowedInUrlsWithoutEncoding(): void
    {
        $domain = str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 61);
        $state = (string)$this->createSigner('cell-1', ['*.' . $domain])->sign(str_repeat('a', 63) . '.' . $domain);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_.-]+\z/', $state);
        self::assertLessThanOrEqual(SignedState::MAXIMUM_LENGTH, strlen($state));
    }

    #[Test]
    public function eachSignedStateHasItsOwnRandomPart(): void
    {
        $signer = $this->createSigner('cell-1');

        self::assertNotSame($signer->sign('acme.example.com')->random, $signer->sign('acme.example.com')->random);
    }

    #[Test]
    public function verifyRefusesStateWithAnotherTargetHost(): void
    {
        $signedState = $this->createSigner('cell-1')->sign('acme.example.com');
        $tamperedState = SignedState::create($signedState->keyId, 'attacker.example.net', $signedState->issuedAt, $signedState->random, $signedState->signature);

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862950);
        $this->createVerifier('cell-1')->verify((string)$tamperedState);
    }

    #[Test]
    public function verifyRefusesStateWithAnotherRandomPart(): void
    {
        $signedState = $this->createSigner('cell-1')->sign('acme.example.com');
        $tamperedState = SignedState::create($signedState->keyId, $signedState->targetHost, $signedState->issuedAt, bin2hex(random_bytes(16)), $signedState->signature);

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862950);
        $this->createVerifier('cell-1')->verify((string)$tamperedState);
    }

    #[Test]
    public function verifyRefusesStateWithForgedSignature(): void
    {
        $signedState = $this->createSigner('cell-1')->sign('acme.example.com');
        $forgedState = SignedState::create($signedState->keyId, $signedState->targetHost, $signedState->issuedAt, $signedState->random, random_bytes(SODIUM_CRYPTO_SIGN_BYTES));

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862950);
        $this->createVerifier('cell-1')->verify((string)$forgedState);
    }

    #[Test]
    public function verifyRefusesStateSignedWithAnotherKeyUnderTheSameKeyId(): void
    {
        $otherKeyPair = StateSigner::generateKeyPair();
        $signedState = StateSigner::fromBase64EncodedSecretKey('cell-1', $otherKeyPair['secretKey'], ['acme.example.com'])->sign('acme.example.com');

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862950);
        $this->createVerifier('cell-1')->verify((string)$signedState);
    }

    #[Test]
    public function verifyRefusesStateWhoseKeyIdWasChanged(): void
    {
        $signedState = $this->createSigner('cell-1')->sign('acme.example.com');
        $verifier = new StateVerifier([
            StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $this->keyPair['publicKey'], ['acme.example.com']),
            StateVerificationKey::fromBase64EncodedPublicKey('cell-2', $this->keyPair['publicKey'], ['acme.example.com']),
        ]);
        $tamperedState = SignedState::create('cell-2', $signedState->targetHost, $signedState->issuedAt, $signedState->random, $signedState->signature);

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862950);
        $verifier->verify((string)$tamperedState);
    }

    #[Test]
    public function verifyRefusesStateSignedWithoutThePurposeOfTheSignature(): void
    {
        $random = bin2hex(random_bytes(16));
        $signedMessage = substr(SignedState::renderSignedMessage('cell-1', 'acme.example.com', time(), $random), strlen('flownative-oauth2-state.'));
        $signature = sodium_crypto_sign_detached($signedMessage, base64_decode($this->keyPair['secretKey']));
        $state = $signedMessage . '.' . sodium_bin2base64($signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

        self::assertStringStartsWith('v1.cell-1.', $state);
        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862950);
        $this->createVerifier('cell-1')->verify($state);
    }

    #[Test]
    public function verifyRefusesUnknownKeyId(): void
    {
        $signedState = $this->createSigner('cell-2')->sign('acme.example.com');

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862949);
        $this->createVerifier('cell-1')->verify((string)$signedState);
    }

    #[Test]
    public function verifyRefusesTargetHostOutsideOfTheHostsOfTheKey(): void
    {
        $signedState = $this->createSigner('cell-1')->sign('acme.other-cell.example.com');

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862951);
        (new StateVerifier([StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $this->keyPair['publicKey'], ['*.cell-1.example.com', 'acme.com'])]))->verify((string)$signedState);
    }

    public static function hostPatternMatches(): array
    {
        return [
            'exact host' => ['acme.com', 'acme.com', true],
            'exact host in other case' => ['ACME.com', 'acme.com', true],
            'exact host with port' => ['acme.com:8443', 'acme.com:8443', true],
            'other port' => ['acme.com:8443', 'acme.com:9443', false],
            'port of exact host missing in pattern' => ['acme.com', 'acme.com:8443', false],
            'subdomain of exact host' => ['acme.com', 'www.acme.com', false],
            'one label below wildcard' => ['*.cell-1.example.com', 'acme.cell-1.example.com', true],
            'wildcard domain itself' => ['*.cell-1.example.com', 'cell-1.example.com', false],
            'two labels below wildcard' => ['*.cell-1.example.com', 'a.acme.cell-1.example.com', false],
            'wildcard domain as suffix of a label' => ['*.cell-1.example.com', 'evilcell-1.example.com', false],
            'one label below wildcard with port' => ['*.cell-1.example.com', 'acme.cell-1.example.com:8443', false],
            'label below wildcard starting like a hexadecimal number' => ['*.cell-1.example.com', '0xide.cell-1.example.com', true],
            'listed IP address' => ['192.0.2.1', '192.0.2.1', true],
            'listed IP address with port' => ['192.0.2.1:8443', '192.0.2.1:8443', true],
            'IP address below wildcard' => ['*.0.2.1', '192.0.2.1', false],
        ];
    }

    #[Test]
    #[DataProvider('hostPatternMatches')]
    public function verificationKeyAllowsOnlyHostsMatchingItsPatterns(string $allowedHostPattern, string $targetHost, bool $expectedResult): void
    {
        $key = StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $this->keyPair['publicKey'], [$allowedHostPattern]);

        self::assertSame($expectedResult, $key->allowsTargetHost($targetHost));
    }

    #[Test]
    public function verificationKeyAllowingAnyHostAllowsAnyHostName(): void
    {
        $key = StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey']);

        self::assertTrue($key->allowsTargetHost('anything.example.org'));
    }

    #[Test]
    public function verificationKeyAllowingAnyHostRefusesIpAddresses(): void
    {
        $key = StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey']);

        self::assertFalse($key->allowsTargetHost('192.0.2.1'));
        self::assertFalse($key->allowsTargetHost('10.0.0.1:8443'));
    }

    public static function alternativeIpAddressNotations(): array
    {
        return [
            'decimal' => ['2130706433'],
            'decimal with port' => ['2130706433:8443'],
            'hexadecimal' => ['0x7f000001'],
            'hexadecimal label' => ['0x7f.0.0.1'],
            'hexadecimal last label' => ['127.0.0.0x1'],
            'octal' => ['0177.0.0.1'],
            'shortened to two parts' => ['127.1'],
            'shortened to three parts' => ['127.0.1'],
        ];
    }

    #[Test]
    #[DataProvider('alternativeIpAddressNotations')]
    public function verificationKeyAllowingAnyHostRefusesAlternativeIpAddressNotations(string $targetHost): void
    {
        $key = StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey']);

        self::assertFalse($key->allowsTargetHost($targetHost));
    }

    #[Test]
    public function verificationKeyAllowingAnyHostAllowsHostNamesWithDigits(): void
    {
        $key = StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey']);

        self::assertTrue($key->allowsTargetHost('1password.example.org'));
        self::assertTrue($key->allowsTargetHost('acme-0x1.example.org'));
        self::assertTrue($key->allowsTargetHost('0xbeef.example.org'));
    }

    #[Test]
    public function verificationKeyAllowingAnyHostRefusesMalformedHosts(): void
    {
        $key = StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey']);

        self::assertFalse($key->allowsTargetHost('[::1]'));
    }

    #[Test]
    public function verifyRefusesIpAddressWhichTheKeyDoesNotListExactly(): void
    {
        $state = (string)$this->createSigner('cell-1', ['192.0.2.1'])->sign('192.0.2.1');

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793862951);
        $this->createVerifier('cell-1')->verify($state);
    }

    #[Test]
    public function signerRefusesHostOutsideOfItsPatterns(): void
    {
        $this->expectException(TargetHostNotAllowedException::class);
        $this->expectExceptionCode(1793863400);
        $this->createSigner('cell-1', ['*.cell-1.example.com'])->sign('evil.tld');
    }

    #[Test]
    public function signerSignsHostWhichItsCheckKnows(): void
    {
        $checkedHosts = [];
        $signer = StateSigner::fromBase64EncodedSecretKey('cell-1', $this->keyPair['secretKey'], ['*.cell-1.example.com'], function (string $targetHost) use (&$checkedHosts): bool {
            $checkedHosts[] = $targetHost;
            return $targetHost === 'acme.cell-1.example.com';
        });

        self::assertSame('acme.cell-1.example.com', $this->createVerifier('cell-1')->verify((string)$signer->sign('ACME.cell-1.example.com'))->targetHost);
        self::assertSame(['acme.cell-1.example.com'], $checkedHosts);
    }

    #[Test]
    public function signerRefusesHostWhichItsCheckDoesNotKnow(): void
    {
        $signer = StateSigner::fromBase64EncodedSecretKey('cell-1', $this->keyPair['secretKey'], ['*.cell-1.example.com'], fn (string $targetHost): bool => $targetHost === 'acme.cell-1.example.com');

        $this->expectException(TargetHostNotAllowedException::class);
        $this->expectExceptionCode(1793949981);
        $signer->sign('dangling.cell-1.example.com');
    }

    #[Test]
    public function signerRefusesHostWhenItsCheckFails(): void
    {
        $failure = new RuntimeException('The tenant database is unreachable.');
        $signer = StateSigner::fromBase64EncodedSecretKey('cell-1', $this->keyPair['secretKey'], ['*.cell-1.example.com'], fn (string $targetHost): bool => throw $failure);

        try {
            $signer->sign('acme.cell-1.example.com');
            self::fail('The signer signed a host although its check failed.');
        } catch (TargetHostNotAllowedException $exception) {
            self::assertSame(1793950325, $exception->getCode());
            self::assertSame($failure, $exception->getPrevious());
        }
    }

    #[Test]
    public function signerAsksItsCheckOnlyForHostsMatchingItsPatterns(): void
    {
        $signer = StateSigner::fromBase64EncodedSecretKey('cell-1', $this->keyPair['secretKey'], ['*.cell-1.example.com'], fn (string $targetHost): bool => self::fail('The check was asked for a host outside of the patterns.'));

        $this->expectException(TargetHostNotAllowedException::class);
        $this->expectExceptionCode(1793863400);
        $signer->sign('evil.tld');
    }

    #[Test]
    public function signerRefusesIpAddressWhichItsPatternsDoNotListExactly(): void
    {
        $this->expectException(TargetHostNotAllowedException::class);
        $this->expectExceptionCode(1793863400);
        $this->createSigner('cell-1', ['*.0.2.1'])->sign('192.0.2.1');
    }

    #[Test]
    public function signerHidesItsSecretKeyFromDebugOutput(): void
    {
        $signer = $this->createSigner('cell-1');

        self::assertStringNotContainsString(bin2hex(base64_decode($this->keyPair['secretKey'])), bin2hex(print_r($signer, true)));
    }

    #[Test]
    public function verifierRejectsDuplicateKeyId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793863401);
        new StateVerifier([
            StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey']),
            StateVerificationKey::allowingAnyHost('cell-1', StateSigner::generateKeyPair()['publicKey']),
        ]);
    }

    #[Test]
    public function verifyAcceptsStateWithinTheMaximumAgeAndTheClockSkew(): void
    {
        $verifier = new StateVerifier([StateVerificationKey::allowingAnyHost('cell-1', $this->keyPair['publicKey'])], maximumAge: 600, clockSkew: 30);

        self::assertSame('acme.example.com', $verifier->verify($this->signWithIssueTime('acme.example.com', time() - 620))->targetHost);
        self::assertSame('acme.example.com', $verifier->verify($this->signWithIssueTime('acme.example.com', time() + 20))->targetHost);
    }

    #[Test]
    public function verifyRefusesExpiredState(): void
    {
        $state = $this->signWithIssueTime('acme.example.com', time() - StateVerifier::DEFAULT_MAXIMUM_AGE - StateVerifier::DEFAULT_CLOCK_SKEW - 10);

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793863403);
        $this->createVerifier('cell-1')->verify($state);
    }

    #[Test]
    public function verifyRefusesStateIssuedInTheFuture(): void
    {
        $state = $this->signWithIssueTime('acme.example.com', time() + StateVerifier::DEFAULT_CLOCK_SKEW + 10);

        $this->expectException(InvalidSignedStateException::class);
        $this->expectExceptionCode(1793863402);
        $this->createVerifier('cell-1')->verify($state);
    }

    public static function invalidHostPatterns(): array
    {
        return [
            'empty' => [''],
            'only wildcard prefix' => ['*.'],
            'wildcard alone' => ['*'],
            'wildcard inside' => ['acme.*.example.com'],
            'wildcard without dot' => ['*example.com'],
            'port above 65535' => ['acme.com:65536'],
            'wildcard below a top-level domain' => ['*.com'],
        ];
    }

    #[Test]
    #[DataProvider('invalidHostPatterns')]
    public function verificationKeyRejectsInvalidHostPatterns(string $allowedHostPattern): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793862948);
        StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $this->keyPair['publicKey'], [$allowedHostPattern]);
    }

    public static function malformedStates(): array
    {
        $host = 'YWNtZS5jb20';
        $random = '0123456789abcdef0123456789abcdef';
        $signature = str_repeat('A', 86);
        return [
            'random state' => [$random],
            'unknown version' => ["v0.cell-1.$host.1793863397.$random.$signature"],
            'missing segment' => ["v1.cell-1.$host.$random.$signature"],
            'additional segment' => ["v1.cell-1.$host.1793863397.$random.$signature.x"],
            'host not base64url' => ["v1.cell-1.YWNt+S5jb20.1793863397.$random.$signature"],
            'host with path' => ['v1.cell-1.' . sodium_bin2base64('acme.com/evil', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) . ".1793863397.$random.$signature"],
            'host with user info' => ['v1.cell-1.' . sodium_bin2base64('user@acme.com', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) . ".1793863397.$random.$signature"],
            'port above 65535' => ['v1.cell-1.' . sodium_bin2base64('acme.com:65536', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) . ".1793863397.$random.$signature"],
            'issue time not a number' => ["v1.cell-1.$host.1793863397x.$random.$signature"],
            'issue time negative' => ["v1.cell-1.$host.-1.$random.$signature"],
            'issue time with leading zero' => ["v1.cell-1.$host.01793863397.$random.$signature"],
            'short random part' => ["v1.cell-1.$host.1793863397.0123.$signature"],
            'short signature' => ["v1.cell-1.$host.1793863397.$random." . str_repeat('A', 43)],
            'too long' => ["v1.cell-1.$host.1793863397." . str_repeat('a', SignedState::MAXIMUM_LENGTH)],
        ];
    }

    #[Test]
    #[DataProvider('malformedStates')]
    public function verifyRefusesMalformedStates(string $state): void
    {
        $this->expectException(InvalidSignedStateException::class);
        $this->createVerifier('cell-1')->verify($state);
    }

    #[Test]
    public function signerRejectsSecretKeyOfWrongLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793862944);
        StateSigner::fromBase64EncodedSecretKey('cell-1', $this->keyPair['publicKey'], ['acme.com']);
    }

    #[Test]
    public function signerRejectsMalformedKeyId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793862945);
        StateSigner::fromBase64EncodedSecretKey('cell.1', $this->keyPair['secretKey'], ['acme.com']);
    }

    public static function malformedTargetHosts(): array
    {
        return [
            'path' => ['acme/evil.example.com'],
            'trailing dot' => ['acme.example.com.'],
            'underscore' => ['foo_bar.example.com'],
            'leading hyphen' => ['-x.example.com'],
        ];
    }

    #[Test]
    #[DataProvider('malformedTargetHosts')]
    public function signerRefusesMalformedTargetHost(string $targetHost): void
    {
        $this->expectException(TargetHostNotAllowedException::class);
        $this->expectExceptionCode(1793950379);
        $this->createSigner('cell-1', ['*.example.com'])->sign($targetHost);
    }

    #[Test]
    public function signerRejectsEmptyListOfHostPatterns(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793863778);
        StateSigner::fromBase64EncodedSecretKey('cell-1', $this->keyPair['secretKey'], []);
    }

    #[Test]
    public function verificationKeyRejectsEmptyListOfHostPatterns(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793863778);
        StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $this->keyPair['publicKey'], []);
    }

    #[Test]
    public function verificationKeyRejectsPublicKeyOfWrongLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1793862947);
        StateVerificationKey::fromBase64EncodedPublicKey('cell-1', $this->keyPair['secretKey'], ['acme.com']);
    }

    /**
     * @param list<string> $allowedHostPatterns
     */
    private function createSigner(string $keyId, array $allowedHostPatterns = ['acme.example.com', 'acme.example.com:8443', 'acme.other-cell.example.com']): StateSigner
    {
        return StateSigner::fromBase64EncodedSecretKey($keyId, $this->keyPair['secretKey'], $allowedHostPatterns);
    }

    private function createVerifier(string $keyId): StateVerifier
    {
        return new StateVerifier([StateVerificationKey::allowingAnyHost($keyId, $this->keyPair['publicKey'])]);
    }

    private function signWithIssueTime(string $targetHost, int $issuedAt): string
    {
        $random = bin2hex(random_bytes(16));
        $signature = sodium_crypto_sign_detached(SignedState::renderSignedMessage('cell-1', $targetHost, $issuedAt, $random), base64_decode($this->keyPair['secretKey']));
        return (string)SignedState::create('cell-1', $targetHost, $issuedAt, $random, $signature);
    }
}
