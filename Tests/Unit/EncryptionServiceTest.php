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

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;
use SodiumException;

class EncryptionServiceTest extends TestCase
{
    #[Test]
    public function encryptedDataCanBeDecryptedWithTheSameKey(): void
    {
        $encryptionService = self::createEncryptionService();

        $encryptedData = $encryptionService->encryptAndEncode('some secret data');

        self::assertStringStartsWith('ChaCha20-Poly1305-IETF$', $encryptedData);
        self::assertStringNotContainsString('some secret data', $encryptedData);
        self::assertSame('some secret data', $encryptionService->decodeAndDecrypt($encryptedData));
    }

    #[Test]
    public function encryptingTheSameDataTwiceGivesDifferentResults(): void
    {
        $encryptionService = self::createEncryptionService();

        self::assertNotSame($encryptionService->encryptAndEncode('data'), $encryptionService->encryptAndEncode('data'));
    }

    #[Test]
    public function decodeAndDecryptFailsWithAnotherKey(): void
    {
        $encryptedData = self::createEncryptionService()->encryptAndEncode('data');

        $this->expectException(SodiumException::class);
        self::createEncryptionService()->decodeAndDecrypt($encryptedData);
    }

    #[Test]
    public function decodeAndDecryptFailsForModifiedData(): void
    {
        $encryptionService = self::createEncryptionService();
        [$construction, $encodedNonce, $encodedData] = explode('$', $encryptionService->encryptAndEncode('data'));
        $data = base64_decode($encodedData);
        $data[0] = $data[0] ^ "\x01";

        $this->expectException(SodiumException::class);
        $encryptionService->decodeAndDecrypt($construction . '$' . $encodedNonce . '$' . base64_encode($data));
    }

    #[Test]
    public function decodeAndDecryptRejectsUnsupportedConstruction(): void
    {
        $encryptionService = self::createEncryptionService();
        [, $encodedNonce, $encodedData] = explode('$', $encryptionService->encryptAndEncode('data'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1604938723);
        $encryptionService->decodeAndDecrypt('AES-256-GCM$' . $encodedNonce . '$' . $encodedData);
    }

    #[Test]
    public function initializeObjectUsesTheConfiguredKey(): void
    {
        $key = (new EncryptionService())->generateEncryptionKey();
        $encryptionService = new EncryptionService();
        (new ReflectionProperty($encryptionService, 'base64EncodedKey'))->setValue($encryptionService, base64_encode($key));

        $encryptionService->initializeObject();

        $otherEncryptionService = new EncryptionService();
        $otherEncryptionService->setKey($key);
        self::assertTrue($encryptionService->isConfigured());
        self::assertSame('data', $otherEncryptionService->decodeAndDecrypt($encryptionService->encryptAndEncode('data')));
    }

    #[Test]
    public function initializeObjectRejectsKeyWhichIsNotBase64Encoded(): void
    {
        $encryptionService = new EncryptionService();
        (new ReflectionProperty($encryptionService, 'base64EncodedKey'))->setValue($encryptionService, 'not base64!');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1604935600);
        $encryptionService->initializeObject();
    }

    #[Test]
    public function initializeObjectRejectsKeyOfWrongLength(): void
    {
        $encryptionService = new EncryptionService();
        (new ReflectionProperty($encryptionService, 'base64EncodedKey'))->setValue($encryptionService, base64_encode('too short'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1789145563);
        $encryptionService->initializeObject();
    }

    #[Test]
    public function encryptionIsNotConfiguredWithoutKey(): void
    {
        $encryptionService = new EncryptionService();

        $encryptionService->initializeObject();

        self::assertFalse($encryptionService->isConfigured());
    }

    #[Test]
    public function generateEncryptionKeyReturnsKeyOfTheRequiredLength(): void
    {
        self::assertSame(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES, strlen((new EncryptionService())->generateEncryptionKey()));
    }

    private static function createEncryptionService(): EncryptionService
    {
        $encryptionService = new EncryptionService();
        $encryptionService->setKey($encryptionService->generateEncryptionKey());
        return $encryptionService;
    }
}
