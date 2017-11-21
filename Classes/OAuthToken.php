<?php
namespace Flownative\OAuth2\Client;

use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations as Flow;

/**
 * Cache / read model for an Oauth2 token
 *
 * @Flow\Entity
 */
class OAuthToken
{
    /**
     * @ORM\Id
     * @var string
     */
    public $clientId;

    /**
     * @ORM\Id
     * @var string
     */
    public $serviceName;

    /**
     * @var string
     */
    public $clientSecret;

    /**
     * @var string
     */
    public $accessToken;

    /**
     * @var string
     */
    public $refreshToken;

    /**
     * @var \DateTimeImmutable
     * @ORM\Column(nullable = true)
     */
    public $expires;

    /**
     * @var string
     */
    public $scope;
}
