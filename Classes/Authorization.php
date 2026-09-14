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
use Ramsey\Uuid\Uuid;

/**
 * An OAuth2 Authorization
 *
 * The mapping uses annotations instead of attributes, because Flow 8.3 reads the Doctrine mapping of entities only from annotations.
 *
 * @Flow\Entity
 */
class Authorization
{
    public const string GRANT_AUTHORIZATION_CODE = 'authorization_code';
    public const string GRANT_CLIENT_CREDENTIALS = 'client_credentials';

    /**
     * @var string
     * @ORM\Id
     */
    protected $authorizationId;

    /**
     * @var string
     */
    protected $serviceName;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $grantType;

    /**
     * @var string
     * @ORM\Column(type="text")
     */
    protected $scope;

    /**
     * @var \DateTimeImmutable
     * @ORM\Column(nullable=true)
     */
    protected $expires;

    /**
     * @var string
     * @ORM\Column(type="text", nullable=true)
     */
    protected $serializedAccessToken;

    /**
     * @var string
     * @ORM\Column(type="text", nullable=true)
     */
    protected $encryptedSerializedAccessToken;

    /**
     * @var string
     * @ORM\Column(type="text", nullable=true)
     */
    protected $metadata;

    /**
     * @var EncryptionService
     * @Flow\Transient
     */
    protected $encryptionService;

    public function __construct(string $authorizationId, string $serviceName, string $clientId, string $grantType, string $scope)
    {
        $this->authorizationId = $authorizationId;
        $this->serviceName = $serviceName;
        $this->clientId = $clientId;
        $this->grantType = $grantType;
        $this->scope = $scope;
    }

    public function injectEncryptionService(EncryptionService $encryptionService): void
    {
        $this->encryptionService = $encryptionService;
    }

    /**
     * Calculate an authorization identifier (for this model) from the given parameters.
     *
     * @throws OAuthClientException
     */
    public static function generateAuthorizationIdForAuthorizationCodeGrant(string $serviceType, string $serviceName, string $clientId): string
    {
        try {
            return $serviceType . '-' . $serviceName . '-' . Uuid::uuid4()->toString();
            // @codeCoverageIgnoreStart
        } catch (\Exception $e) {
            throw new OAuthClientException(sprintf('Failed generating authorization id for %s %s', $serviceName, $clientId), 1597311416, $e);
        }
        // @codeCoverageIgnoreEnd
    }

    /**
     * Calculate the authorization identifier of a client credentials grant from the given parameters.
     *
     * The client secret is not part of the identifier, so that the identifier, which appears in logs and in the command line, reveals nothing about it.
     */
    public static function generateAuthorizationIdForClientCredentialsGrant(string $serviceName, string $clientId, string $scope, array $additionalParameters = []): string
    {
        try {
            return hash('sha256', json_encode([self::GRANT_CLIENT_CREDENTIALS, $serviceName, $clientId, $scope, $additionalParameters], JSON_THROW_ON_ERROR));
        } catch (\JsonException $exception) {
            throw new \InvalidArgumentException('The additional parameters of the client credentials grant cannot be encoded as JSON', 1789391048, $exception);
        }
    }

    public function getAuthorizationId(): string
    {
        return $this->authorizationId;
    }

    public function getServiceName(): string
    {
        return $this->serviceName;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getGrantType(): string
    {
        return $this->grantType;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function setScope(string $scope): void
    {
        $this->scope = $scope;
    }

    public function getSerializedAccessToken(): string
    {
        return $this->serializedAccessToken ?? '';
    }

    public function setSerializedAccessToken(string $serializedAccessToken): void
    {
        $this->serializedAccessToken = $serializedAccessToken;
    }

    public function getEncryptedSerializedAccessToken(): string
    {
        return $this->encryptedSerializedAccessToken ?? '';
    }

    public function setEncryptedSerializedAccessToken(string $encryptedSerializedAccessToken): void
    {
        $this->encryptedSerializedAccessToken = $encryptedSerializedAccessToken;
    }

    /**
     * @throws \InvalidArgumentException
     */
    public function setAccessToken(AccessTokenInterface $accessToken): void
    {
        $expirationTimestamp = $accessToken->getExpires();
        if ($expirationTimestamp) {
            $this->setExpires(\DateTimeImmutable::createFromFormat('U', (string)$expirationTimestamp));
        }

        try {
            // The column of the other storage format is cleared, so that no unencrypted token stays behind once encryption is configured
            if ($this->encryptionService !== null && $this->encryptionService->isConfigured()) {
                $this->encryptedSerializedAccessToken = $this->encryptionService->encryptAndEncode(json_encode($accessToken, JSON_THROW_ON_ERROR));
                $this->serializedAccessToken = null;
            } else {
                $this->serializedAccessToken = json_encode($accessToken, JSON_THROW_ON_ERROR);
                $this->encryptedSerializedAccessToken = null;
            }
            // @codeCoverageIgnoreStart
        } catch (\JsonException | \Exception $e) {
            throw new \InvalidArgumentException('Failed serializing the given access token', 1602515717, $e);
            // @codeCoverageIgnoreEnd
        }
    }

    /**
     * Returns null if no token is stored or if the stored token cannot be decrypted with the current key
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
        } catch (\JsonException | \SodiumException) {
        }
        return null;
    }

    public function getExpires(): ?\DateTimeImmutable
    {
        // Doctrine loads the stored UTC time with PHP's default time zone.
        return $this->expires !== null ? new \DateTimeImmutable($this->expires->format('Y-m-d H:i:s'), new \DateTimeZone('UTC')) : null;
    }

    /**
     * The expiration time is stored in UTC, so that garbage collection does not depend on PHP's default time zone
     */
    public function setExpires(?\DateTimeImmutable $expires): void
    {
        $this->expires = $expires?->setTimezone(new \DateTimeZone('UTC'));
    }

    public function getMetadata(): ?string
    {
        return $this->metadata;
    }

    public function setMetadata(string $metadata): void
    {
        $this->metadata = $metadata;
    }
}
