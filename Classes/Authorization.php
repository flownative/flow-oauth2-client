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

use Doctrine\ORM\Mapping as ORM;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Neos\Flow\Annotations as Flow;

/**
 * An OAuth2 Authorization
 *
 * @Flow\Entity
 */
class Authorization
{
    public const GRANT_AUTHORIZATION_CODE = 'authorization_code';
    public const GRANT_CLIENT_CREDENTIALS = 'client_credentials';

    /**
     * @ORM\Id
     * @var string
     */
    protected $authorizationId;

    /**
     * @var string
     */
    protected $serviceName;

    /**
     * /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     * @ORM\Column(nullable = true, length=5000)
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $grantType;

    /**
     * @var string
     */
    protected $scope;

    /**
     * @var \DateTimeImmutable
     * @ORM\Column(nullable = true)
     */
    protected $expires;

    /**
     * @var array
     * @ORM\Column(type="json_array", nullable = true)
     */
    protected $serializedAccessToken;

    /**
     * @param string $serviceName
     * @param string $clientId
     * @param string $grantType
     * @param string $scope
     */
    public function __construct(string $serviceName, string $clientId, string $grantType, string $scope)
    {
        $this->authorizationId = self::calculateAuthorizationId($serviceName, $clientId, $scope, $grantType);
        $this->serviceName = $serviceName;
        $this->clientId = $clientId;
        $this->grantType = $grantType;
        $this->scope = $scope;
    }

    /**
     * Calculate an authorization identifier (for this model) from the given parameters.
     *
     * @param string $serviceName
     * @param string $clientId
     * @param string $scope
     * @param string $grantType
     * @return string
     */
    public static function calculateAuthorizationId(string $serviceName, string $clientId, string $scope, string $grantType): string
    {
        return sha1($serviceName . $clientId . $scope . $grantType);
    }

    /**
     * @return string
     */
    public function getAuthorizationId(): string
    {
        return $this->authorizationId;
    }

    /**
     * @return string
     */
    public function getServiceName(): string
    {
        return $this->serviceName;
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * @param string $clientSecret
     */
    public function setClientSecret(string $clientSecret): void
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    public function getGrantType(): string
    {
        return $this->grantType;
    }

    /**
     * @return string
     * @return void
     */
    public function getScope(): string
    {
        return $this->scope;
    }

    /**
     * @param string $scope
     */
    public function setScope(string $scope): void
    {
        $this->scope = $scope;
    }

    /**
     * @return array
     */
    public function getSerializedAccessToken(): array
    {
        return $this->serializedAccessToken ?? [];
    }

    /**
     * @param array $serializedAccessToken
     */
    public function setSerializedAccessToken(array $serializedAccessToken): void
    {
        $this->serializedAccessToken = $serializedAccessToken;
    }

    /**
     * @param AccessTokenInterface $accessToken
     * @return void
     */
    public function setAccessToken(AccessTokenInterface $accessToken): void
    {
        $this->serializedAccessToken = $accessToken->jsonSerialize();
    }

    /**
     * @return AccessToken
     */
    public function getAccessToken(): ?AccessToken
    {
        return !empty($this->serializedAccessToken) ? new AccessToken($this->serializedAccessToken) : null;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpires(): \DateTimeImmutable
    {
        return $this->expires;
    }

    /**
     * @param \DateTimeImmutable $expires
     */
    public function setExpires(\DateTimeImmutable $expires): void
    {
        $this->expires = $expires;
    }
}
