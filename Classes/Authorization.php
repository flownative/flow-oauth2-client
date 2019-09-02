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
     * @var array
     * @ORM\Column(type="json_array", nullable = true)
     */
    protected $serializedAccessToken;

    /**
     * @param string $serviceName
     * @param string $clientId
     * @param string $clientSecret
     * @param string $grantType
     * @param string $scope
     */
    public function __construct(string $serviceName, string $clientId, string $clientSecret, string $grantType, string $scope)
    {
        $this->serviceName = $serviceName;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->grantType = $grantType;
        $this->scope = $scope;
        $this->authorizationId = sha1($serviceName . $clientId . $grantType . $scope);
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
    public function getAccessToken(): ?AccessTokenInterface
    {
        return !empty($this->serializedAccessToken) ? new AccessToken($this->serializedAccessToken) : null;
    }
}
