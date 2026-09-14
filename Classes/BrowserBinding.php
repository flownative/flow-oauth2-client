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
use Neos\Flow\Http\Cookie;

/**
 * Binds an authorization to the browser which started it
 *
 * The browser keeps a random secret in a cookie, and the OAuth client only stores the hash of this secret. The return from the OAuth
 * server and the authorization handle are only accepted from a browser which sends the matching secret. An attacker can therefore
 * neither finish an authorization of their own in the browser of a victim, nor claim an authorization with a handle found in a log.
 *
 * Applications which keep a random secret for the login in a cookie anyway, like the nonce of OpenID Connect, can use that cookie.
 */
#[Flow\Proxy(false)]
final readonly class BrowserBinding
{
    private const string COOKIE_NAME_PREFIX = 'flownative_oauth2_binding_';
    private const int COOKIE_LIFETIME = 3600; # seconds, the lifetime of the state of an authorization
    private const int MINIMUM_SECRET_LENGTH = 32;

    private function __construct(
        public string $cookieName,
        private string $secret,
        private bool $secureCookie,
    ) {
    }

    /**
     * @param bool $secureCookie false only for development without HTTPS, because such a cookie can't have the "__Host-" prefix
     */
    public static function generate(bool $secureCookie = true): self
    {
        // Each authorization gets its own cookie, so that authorizations started in parallel, for example in two tabs, don't replace each other's secret
        $cookieName = ($secureCookie ? '__Host-' : '') . self::COOKIE_NAME_PREFIX . bin2hex(random_bytes(8));
        return new self($cookieName, bin2hex(random_bytes(32)), $secureCookie);
    }

    /**
     * Uses a random secret which the application already keeps in the given cookie
     */
    public static function fromExistingCookie(string $cookieName, string $secret): self
    {
        if ($cookieName === '' || strlen($secret) < self::MINIMUM_SECRET_LENGTH) {
            throw new InvalidArgumentException(sprintf('A browser binding needs a cookie name and a secret of at least %d characters.', self::MINIMUM_SECRET_LENGTH), 1789395651);
        }
        return new self($cookieName, $secret, self::hasSecurePrefix($cookieName));
    }

    public function getSecretHash(): string
    {
        return hash('sha256', $this->secret);
    }

    /**
     * Returns the cookie which the response that redirects the browser to the OAuth server must set
     */
    public function createCookie(): Cookie
    {
        // A "strict" cookie would not be sent when the OAuth server redirects the browser back
        return new Cookie($this->cookieName, $this->secret, 0, self::COOKIE_LIFETIME, null, '/', $this->secureCookie, true, Cookie::SAMESITE_LAX);
    }

    /**
     * Tells if the given cookies contain the secret whose hash was stored when the authorization started
     */
    public static function isPresentInCookies(string $cookieName, string $secretHash, array $cookies): bool
    {
        $secret = $cookies[$cookieName] ?? null;
        return $secretHash !== '' && is_string($secret) && hash_equals($secretHash, hash('sha256', $secret));
    }

    public static function createRemovalCookie(string $cookieName): Cookie
    {
        return new Cookie($cookieName, '', 1, null, null, '/', self::hasSecurePrefix($cookieName), true, Cookie::SAMESITE_LAX);
    }

    private static function hasSecurePrefix(string $cookieName): bool
    {
        return str_starts_with($cookieName, '__Host-') || str_starts_with($cookieName, '__Secure-');
    }
}
