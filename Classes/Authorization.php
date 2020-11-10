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
use Exception;
use InvalidArgumentException;
use JsonException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Neos\Flow\Annotations as Flow;
use Ramsey\Uuid\Uuid;

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
     * @var string
     * @ORM\Column(nullable = true, type = "text")
     */
    protected $serializedAccessToken;

    /**
     * @var string
     * @ORM\Column(nullable = true, type = "text")
     */
    protected $encryptedSerializedAccessToken;

    /**
     * @var EncryptionService
     */
    protected $encryptionService;

    /**
     * @param string $authorizationId
     * @param string $serviceName
     * @param string $clientId
     * @param string $grantType
     * @param string $scope
     */
    public function __construct(string $authorizationId, string $serviceName, string $clientId, string $grantType, string $scope)
    {
        $this->authorizationId = $authorizationId;
        $this->serviceName = $serviceName;
        $this->clientId = $clientId;
        $this->grantType = $grantType;
        $this->scope = $scope;
    }

    /**
     * @param EncryptionService $encryptionService
     */
    public function injectEncryptionService(EncryptionService $encryptionService): void
    {
        $this->encryptionService = $encryptionService;
    }

    /**
     * Calculate an authorization identifier (for this model) from the given parameters.
     *
     * @param string $serviceType
     * @param string $serviceName
     * @param string $clientId
     * @return string
     * @throws OAuthClientException
     */
    public static function generateAuthorizationIdForAuthorizationCodeGrant(string $serviceType, string $serviceName, string $clientId): string
    {
        try {
            return $serviceType . '-' . $serviceName . '-' . Uuid::uuid4()->toString();
            // @codeCoverageIgnoreStart
        } catch (Exception $e) {
            throw new OAuthClientException(sprintf('Failed generating authorization id for %s %s', $serviceName, $clientId), 1597311416, $e);
        }
        // @codeCoverageIgnoreEnd
    }

    /**
     * Calculate an authorization identifier (for this model) from the given parameters.
     *
     * @param string $serviceName
     * @param string $clientId
     * @param string $clientSecret
     * @param string $scope
     * @return string
     */
    public static function generateAuthorizationIdForClientCredentialsGrant(string $serviceName, string $clientId, string $clientSecret, string $scope): string
    {
        return hash('sha512', $serviceName . $clientId . $clientSecret . $scope . self::GRANT_CLIENT_CREDENTIALS);
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
     * @return string
     */
    public function getSerializedAccessToken(): string
    {
        return $this->serializedAccessToken ?? '';
    }

    /**
     * @param string $serializedAccessToken
     */
    public function setSerializedAccessToken(string $serializedAccessToken): void
    {
        $this->serializedAccessToken = $serializedAccessToken;
    }

    /**
     * @return string
     */
    public function getEncryptedSerializedAccessToken(): string
    {
        return $this->encryptedSerializedAccessToken ?? '';
    }

    /**
     * @param string $encryptedSerializedAccessToken
     */
    public function setEncryptedSerializedAccessToken(string $encryptedSerializedAccessToken): void
    {
        $this->encryptedSerializedAccessToken = $encryptedSerializedAccessToken;
    }

    /**
     * @param AccessTokenInterface $accessToken
     * @return void
     * @throws InvalidArgumentException
     */
    public function setAccessToken(AccessTokenInterface $accessToken): void
    {
        try {
            if ($this->encryptionService !== null && $this->encryptionService->isConfigured()) {
                $this->encryptedSerializedAccessToken = $this->encryptionService->encryptAndEncode(json_encode($accessToken, JSON_THROW_ON_ERROR, 512));
            } else {
                $this->serializedAccessToken = json_encode($accessToken, JSON_THROW_ON_ERROR, 512);
            }
            // @codeCoverageIgnoreStart
        } catch (JsonException | Exception $e) {
            throw new InvalidArgumentException('Failed serializing the given access token', 1602515717, $e);
            // @codeCoverageIgnoreEnd
        }
    }

    /**
     * @return AccessToken
     */
    public function getAccessToken(): ?AccessToken
    {
        if (empty($this->serializedAccessToken) && empty($this->encryptedSerializedAccessToken)) {
            return null;
        }
        if (!empty($this->encryptedSerializedAccessToken) && !$this->encryptionService->isConfigured()) {
            return null;
        }
        try {
            if (!empty($this->encryptedSerializedAccessToken)) {
                $deserializedAccessToken = json_decode($this->encryptionService->decodeAndDecrypt($this->encryptedSerializedAccessToken), true, 512, JSON_THROW_ON_ERROR);
                return new AccessToken($deserializedAccessToken);
            }
            if (!empty($this->serializedAccessToken)) {
                $deserializedAccessToken = json_decode($this->serializedAccessToken, true, 512, JSON_THROW_ON_ERROR);
                return new AccessToken($deserializedAccessToken);
            }
        } catch (JsonException $e) {
        }
        return null;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpires(): ?\DateTimeImmutable
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
