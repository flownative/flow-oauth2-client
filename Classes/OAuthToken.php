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
    public $grantType;

    /**
     * @var string
     * @ORM\Column(nullable = true, length=5000)
     */
    public $clientSecret;

    /**
     * @var string
     * @ORM\Column(length=5000)
     */
    public $accessToken;

    /**
     * @var string
     * @ORM\Column(nullable = true, length=5000)
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
