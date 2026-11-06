<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client\Tests\Unit\Fixtures;

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\StateSigner;
use GuzzleHttp\ClientInterface;

class OAuthTestClient extends OAuthClient
{
    public const TEST_SERVICE_TYPE = 'TestServiceType';
    public const TEST_BASE_URI = 'https://localbeach.net/';
    public const TEST_CLIENT_ID = 'my-client-id';
    public const TEST_CLIENT_SECRET = 'the-secret-of-my-client';

    private ?ClientInterface $httpClient = null;

    private string $finishAuthorizationUri = self::TEST_BASE_URI . 'oauth/finish';

    private ?string $redirectUri = null;

    private ?StateSigner $stateSigner = null;

    public function setHttpClient(ClientInterface $httpClient): void
    {
        $this->httpClient = $httpClient;
    }

    public function setFinishAuthorizationUri(string $finishAuthorizationUri): void
    {
        $this->finishAuthorizationUri = $finishAuthorizationUri;
    }

    public function setRedirectUri(?string $redirectUri): void
    {
        $this->redirectUri = $redirectUri;
    }

    public function setStateSigner(?StateSigner $stateSigner): void
    {
        $this->stateSigner = $stateSigner;
    }

    public static function getServiceType(): string
    {
        return self::TEST_SERVICE_TYPE;
    }

    public function getBaseUri(): string
    {
        return self::TEST_BASE_URI;
    }

    public function getClientId(): string
    {
        return self::TEST_CLIENT_ID;
    }

    public function getClientSecret(string $clientId): string
    {
        return self::TEST_CLIENT_SECRET;
    }

    public function renderFinishAuthorizationUri(): string
    {
        return $this->finishAuthorizationUri;
    }

    protected function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    protected function getStateSigner(): ?StateSigner
    {
        return $this->stateSigner;
    }

    protected function createHttpClient(): ClientInterface
    {
        return $this->httpClient ?? parent::createHttpClient();
    }
}
