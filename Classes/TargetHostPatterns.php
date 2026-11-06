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
 * The hosts a key may sign states for, shared by StateSigner and StateVerificationKey
 *
 * A pattern is a host name, with a port if it is not the default one, or "*." followed by a domain, which matches exactly one further
 * label: "*.example.com" matches "acme.example.com", but neither "example.com" nor "a.b.example.com". The domain of a wildcard needs at
 * least two labels. An IP address, also in a notation which browsers resolve such as "2130706433", "0x7f000001" or "127.1", only
 * matches a pattern which names it exactly, never a wildcard and never "any host".
 */
#[Flow\Proxy(false)]
final readonly class TargetHostPatterns
{
    /**
     * @param list<string> $patterns
     */
    private function __construct(
        public array $patterns,
        public bool $anyHost,
    ) {
    }

    /**
     * @param list<string> $patterns
     */
    public static function fromArray(array $patterns): self
    {
        if ($patterns === []) {
            throw new InvalidArgumentException('The list of host patterns is empty; name the hosts a key may sign states for, or trust a verification key with any host explicitly.', 1793863778);
        }
        $patterns = array_values(array_map(strtolower(...), $patterns));
        foreach ($patterns as $pattern) {
            $isWildcard = str_starts_with($pattern, '*.');
            $host = $isWildcard ? substr($pattern, 2) : $pattern;
            if (!SignedState::isValidTargetHost($host) || ($isWildcard && !str_contains($host, '.'))) {
                throw new InvalidArgumentException(sprintf('The host pattern "%s" is invalid.', $pattern), 1793862948);
            }
        }
        return new self($patterns, false);
    }

    public static function anyHost(): self
    {
        return new self([], true);
    }

    public function matches(string $targetHost): bool
    {
        if (!SignedState::isValidTargetHost($targetHost)) {
            return false;
        }
        $isIpAddress = self::isIpAddress(preg_replace('/:[0-9]+\z/', '', $targetHost) ?? $targetHost);
        if ($this->anyHost && !$isIpAddress) {
            return true;
        }
        foreach ($this->patterns as $pattern) {
            if ($pattern === $targetHost) {
                return true;
            }
            if (!$isIpAddress && str_starts_with($pattern, '*.')) {
                $domain = substr($pattern, 1);
                $label = substr($targetHost, 0, -strlen($domain));
                if (str_ends_with($targetHost, $domain) && $label !== '' && !str_contains($label, '.') && !str_contains($label, ':')) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Like browsers, takes every host whose last label is a decimal, octal or hexadecimal number for an IPv4 address
     */
    private static function isIpAddress(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || preg_match('/(^|\.)([0-9]+|0x[0-9a-f]*)\z/', $host) === 1;
    }
}
