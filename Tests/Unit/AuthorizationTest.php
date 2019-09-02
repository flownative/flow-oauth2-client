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

use League\OAuth2\Client\Token\AccessToken;
use Neos\Flow\Tests\UnitTestCase;
use Neos\Flow\Utility\Algorithms;

class AuthorizationTest extends UnitTestCase
{
    /**
     * @return array
     */
    public function correctConstructorArguments(): array
    {
        return [
            [
                '3d47f0eafd6a8b49e32b55103d817b6e4ef489e7',
                'myService',
                'ac36cGG4d2Cef1DeuevA7T1u7V4WOUI14',
                'CMc4EHfyMPLw}Tua%rnyxCnrTWMuX3',
                'authorization_code',
                'profile oidc'
            ]
        ];
    }

    /**
     * @param string $expectedAuthorizationId
     * @param string $serviceName
     * @param string $clientId
     * @param string $clientSecret
     * @param string $grantType
     * @param string $scope
     * @test
     * @dataProvider correctConstructorArguments
     */
    public function constructSetsAuthorizationIdentifier(string $expectedAuthorizationId, string $serviceName, string $clientId, string $clientSecret, string $grantType, string $scope): void
    {
        $authorization = new Authorization($serviceName, $clientId, $clientSecret, $grantType, $scope);
        self::assertSame($expectedAuthorizationId, $authorization->getAuthorizationId());
    }

    /**
     * @test
     */
    public function getAccessTokenReturnsClonedObject(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('service', 'clientId', 'clientSecret', 'authorization_code', '');
        $authorization->setAccessToken($accessToken);
        $retrievedAccessToken = $authorization->getAccessToken();

        $this->assertNotSame($accessToken, $retrievedAccessToken);
        $this->assertEquals($accessToken, $retrievedAccessToken);
    }

    /**
     * @test
     */
    public function getSerializedAccessTokenReturnsCorrectJsonString(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('service', 'clientId', 'clientSecret', 'authorization_code', '');
        $authorization->setAccessToken($accessToken);

        $secondAccessToken = new AccessToken($authorization->getSerializedAccessToken());
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    /**
     * @test
     */
    public function getAccessTokenReturnsPreviouslySetSerializedToken(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('service', 'clientId', 'clientSecret', 'authorization_code', '');
        $authorization->setSerializedAccessToken($accessToken->jsonSerialize());

        $secondAccessToken = new AccessToken($authorization->getSerializedAccessToken());
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    /**
     * @return AccessToken
     */
    private function createValidAccessToken(): AccessToken
    {
        $accessToken = new AccessToken([
            'access_token' => Algorithms::generateRandomToken(500),
            'expires' => time() + 3600
        ]);
        return $accessToken;
    }
}
