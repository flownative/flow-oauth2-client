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

use Exception;
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
                'authorization_code',
                'profile oidc'
            ]
        ];
    }

    /**
     * @param string $authorizationId
     * @param string $serviceName
     * @param string $clientId
     * @param string $grantType
     * @param string $scope
     * @test
     * @dataProvider correctConstructorArguments
     */
    public function constructSetsAuthorizationParameters(string $authorizationId, string $serviceName, string $clientId, string $grantType, string $scope): void
    {
        $authorization = new Authorization($authorizationId, $serviceName, $clientId, $grantType, $scope);
        self::assertSame($authorizationId, $authorization->getAuthorizationId());
        self::assertSame($serviceName, $authorization->getServiceName());
        self::assertSame($clientId, $authorization->getClientId());
        self::assertSame($grantType, $authorization->getGrantType());
        self::assertSame($scope, $authorization->getScope());
    }

    /**
     * @test
     * @throws Exception
     */
    public function getAccessTokenReturnsClonedObject(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId',Authorization::GRANT_AUTHORIZATION_CODE, 'profile');
        $authorization->setAccessToken($accessToken);
        $retrievedAccessToken = $authorization->getAccessToken();

        $this->assertNotSame($accessToken, $retrievedAccessToken);
        $this->assertEquals($accessToken, $retrievedAccessToken);
    }

    /**
     * @test
     * @throws Exception
     */
    public function getSerializedAccessTokenReturnsCorrectJsonString(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId',  Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setAccessToken($accessToken);

        $secondAccessToken = new AccessToken(json_decode($authorization->getSerializedAccessToken(), true, 512, JSON_THROW_ON_ERROR));
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    /**
     * @test
     * @throws Exception
     */
    public function getAccessTokenReturnsPreviouslySetSerializedToken(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setSerializedAccessToken(json_encode($accessToken, JSON_THROW_ON_ERROR, 512));

        $secondAccessToken = new AccessToken(json_decode($authorization->getSerializedAccessToken(), true, 512, JSON_THROW_ON_ERROR));
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    /**
     * @test
     */
    public function generateAuthorizationIdForClientCredentialsGrantReturnsSha1(): void
    {
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant(
            'oidc_test', 'ac36cGG4d2Cef1DeuevA7T1u7V4WOUI14', 'CMc4EHfyMPLw}Tua%rnyxCnrTWMuX3', 'oidc profile'
        );
        self::assertSame('bd55b7bc1b40d6342789c74fcc1900877b3966f4656c5d6a1c0a9111a1da02365ba9f00fcb1d058629446f7ec83d02166b0a8c271cbf1374467e7f294bb4b784', $authorizationId);
    }

    /**
     * @test
     * @throws OAuthClientException
     *
     * @see https://github.com/flownative/flow-oauth2-client/issues/13
     */
    public function generateAuthorizationIdForAuthorizationCodeGrantReturnsRandomIdentifiers(): void
    {
        $firstAuthorizationId = Authorization::generateAuthorizationIdForAuthorizationCodeGrant(
            'oidc_test', 'test', 'ac36cGG4d2Cef1DeuevA7T1u7V4WOUI14'
        );

        self::assertStringStartsWith('oidc_test-test-', $firstAuthorizationId);
        self::assertStringMatchesFormat('oidc_test-test-%x%x%x%x%x%x%x%x-%x%x%x%x-%x%x%x%x-%x%x%x%x-%x%x%x%x%x%x%x%x%x%x%x%x', $firstAuthorizationId);

        $secondAuthorizationId = Authorization::generateAuthorizationIdForAuthorizationCodeGrant(
            'oidc_test', 'test', 'ac36cGG4d2Cef1DeuevA7T1u7V4WOUI14'
        );

        self::assertStringStartsWith('oidc_test-test-', $secondAuthorizationId);
        self::assertStringMatchesFormat('oidc_test-test-%x%x%x%x%x%x%x%x-%x%x%x%x-%x%x%x%x-%x%x%x%x-%x%x%x%x%x%x%x%x%x%x%x%x', $secondAuthorizationId);

        self::assertNotSame($firstAuthorizationId, $secondAuthorizationId);
    }

    /**
     * @test
     */
    public function getAccessTokenReturnsNullIfNoTokenWasSet(): void
    {
        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        self::assertNull($authorization->getAccessToken());
    }

    /**
     * @test
     */
    public function getAccessTokenReturnsNullIfTokenCouldNotBeUnserialized(): void
    {
        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setSerializedAccessToken('invalid json syntax');
        self::assertNull($authorization->getAccessToken());
    }

    /**
     * @test
     */
    public function getScopeReturnsScope(): void
    {
        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setScope('some-custom-scope');
        self::assertSame('some-custom-scope', $authorization->getScope());
    }

    /**
     * @return AccessToken
     * @throws Exception
     */
    private function createValidAccessToken(): AccessToken
    {
        return new AccessToken([
            'access_token' => Algorithms::generateRandomToken(500),
            'expires' => time() + 3600
        ]);
    }
}
