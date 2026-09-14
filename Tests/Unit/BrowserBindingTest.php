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
use Neos\Flow\Http\Cookie;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class BrowserBindingTest extends TestCase
{
    #[Test]
    public function generateCreatesHttpOnlyHostCookie(): void
    {
        $cookie = BrowserBinding::generate()->createCookie();

        self::assertMatchesRegularExpression('/^__Host-flownative_oauth2_binding_[0-9a-f]{16}$/', $cookie->getName());
        self::assertTrue($cookie->isSecure());
        self::assertTrue($cookie->isHttpOnly());
        self::assertSame('/', $cookie->getPath());
        self::assertSame(Cookie::SAMESITE_LAX, $cookie->getSameSite());
        self::assertSame(3600, $cookie->getMaximumAge());
    }

    #[Test]
    public function generateCreatesCookieWithoutPrefixForDevelopmentWithoutHttps(): void
    {
        $cookie = BrowserBinding::generate(false)->createCookie();

        self::assertStringStartsWith('flownative_oauth2_binding_', $cookie->getName());
        self::assertFalse($cookie->isSecure());
    }

    #[Test]
    public function generateCreatesDifferentCookieNamesAndSecrets(): void
    {
        $firstBinding = BrowserBinding::generate();
        $secondBinding = BrowserBinding::generate();

        self::assertNotSame($firstBinding->cookieName, $secondBinding->cookieName);
        self::assertNotSame($firstBinding->getSecretHash(), $secondBinding->getSecretHash());
    }

    #[Test]
    public function isPresentInCookiesAcceptsOnlyTheSecretOfTheBinding(): void
    {
        $binding = BrowserBinding::generate();
        $cookie = $binding->createCookie();

        self::assertTrue(BrowserBinding::isPresentInCookies($binding->cookieName, $binding->getSecretHash(), [$cookie->getName() => $cookie->getValue()]));
        self::assertFalse(BrowserBinding::isPresentInCookies($binding->cookieName, $binding->getSecretHash(), []));
        self::assertFalse(BrowserBinding::isPresentInCookies($binding->cookieName, $binding->getSecretHash(), [$cookie->getName() => 'forged-secret']));
        self::assertFalse(BrowserBinding::isPresentInCookies($binding->cookieName, $binding->getSecretHash(), [$cookie->getName() => ['array']]));
        self::assertFalse(BrowserBinding::isPresentInCookies($binding->cookieName, '', [$cookie->getName() => $cookie->getValue()]));
    }

    #[Test]
    public function fromExistingCookieUsesTheSecretOfThatCookie(): void
    {
        $secret = str_repeat('a', 64);

        $binding = BrowserBinding::fromExistingCookie('__Host-my_login_cookie', $secret);

        self::assertTrue(BrowserBinding::isPresentInCookies('__Host-my_login_cookie', $binding->getSecretHash(), ['__Host-my_login_cookie' => $secret]));
    }

    #[Test]
    public function fromExistingCookieCreatesSecureCookieByDefault(): void
    {
        $binding = BrowserBinding::fromExistingCookie('my_login_cookie', str_repeat('a', 64));

        self::assertTrue($binding->createCookie()->isSecure());
    }

    #[Test]
    public function fromExistingCookieCreatesInsecureCookieOnlyForNamesWithoutSecurePrefix(): void
    {
        self::assertFalse(BrowserBinding::fromExistingCookie('my_login_cookie', str_repeat('a', 64), false)->createCookie()->isSecure());
        self::assertTrue(BrowserBinding::fromExistingCookie('__Host-my_login_cookie', str_repeat('a', 64), false)->createCookie()->isSecure());
        self::assertTrue(BrowserBinding::fromExistingCookie('__Secure-my_login_cookie', str_repeat('a', 64), false)->createCookie()->isSecure());
    }

    #[Test]
    public function fromExistingCookieRejectsShortSecrets(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1789395651);
        BrowserBinding::fromExistingCookie('__Host-my_login_cookie', 'short');
    }

    #[Test]
    public function createRemovalCookieExpiresTheCookie(): void
    {
        $cookie = BrowserBinding::createRemovalCookie('__Host-flownative_oauth2_binding_0123456789abcdef');

        self::assertSame('', $cookie->getValue());
        self::assertSame(1, $cookie->getExpires());
        self::assertTrue($cookie->isSecure());
    }
}
