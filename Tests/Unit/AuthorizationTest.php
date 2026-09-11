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
use Neos\Flow\Utility\Algorithms;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class AuthorizationTest extends TestCase
{
    public static function correctConstructorArguments(): array
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

    #[Test]
    #[DataProvider('correctConstructorArguments')]
    public function constructSetsAuthorizationParameters(string $authorizationId, string $serviceName, string $clientId, string $grantType, string $scope): void
    {
        $authorization = new Authorization($authorizationId, $serviceName, $clientId, $grantType, $scope);
        self::assertSame($authorizationId, $authorization->getAuthorizationId());
        self::assertSame($serviceName, $authorization->getServiceName());
        self::assertSame($clientId, $authorization->getClientId());
        self::assertSame($grantType, $authorization->getGrantType());
        self::assertSame($scope, $authorization->getScope());
    }

    #[Test]
    public function getAccessTokenReturnsClonedObject(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId',Authorization::GRANT_AUTHORIZATION_CODE, 'profile');
        $authorization->setAccessToken($accessToken);
        $retrievedAccessToken = $authorization->getAccessToken();

        $this->assertNotSame($accessToken, $retrievedAccessToken);
        $this->assertEquals($accessToken, $retrievedAccessToken);
    }

    #[Test]
    public function getSerializedAccessTokenReturnsCorrectJsonString(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId',  Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setAccessToken($accessToken);

        $secondAccessToken = new AccessToken(json_decode($authorization->getSerializedAccessToken(), true, 512, JSON_THROW_ON_ERROR));
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    #[Test]
    public function getAccessTokenReturnsPreviouslySetSerializedToken(): void
    {
        $accessToken = $this->createValidAccessToken();

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setSerializedAccessToken(json_encode($accessToken, JSON_THROW_ON_ERROR, 512));

        $secondAccessToken = new AccessToken(json_decode($authorization->getSerializedAccessToken(), true, 512, JSON_THROW_ON_ERROR));
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    #[Test]
    public function setAccessTokenEncryptsTokenIfEncryptionServiceIsConfigured(): void
    {
        $accessToken = $this->createValidAccessToken();

        $encryptionService = new EncryptionService();
        $encryptionService->setKey($encryptionService->generateEncryptionKey());

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->injectEncryptionService($encryptionService);

        $authorization->setAccessToken($accessToken);
        $this->assertNotEmpty($authorization->getEncryptedSerializedAccessToken());

        $secondAccessToken = $authorization->getAccessToken();
        $this->assertEquals($accessToken, $secondAccessToken);
    }

    #[Test]
    public function getAccessTokenFailsOnEncryptedTokenIfKeyWasChanged(): void
    {
        $accessToken = $this->createValidAccessToken();

        $encryptionService = new EncryptionService();
        $encryptionService->setKey($encryptionService->generateEncryptionKey());

        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->injectEncryptionService($encryptionService);

        $authorization->setAccessToken($accessToken);
        $this->assertNotEmpty($authorization->getEncryptedSerializedAccessToken());

        // Change the key so that decryption fails:
        $encryptionService->setKey($encryptionService->generateEncryptionKey());

        $secondAccessToken = $authorization->getAccessToken();
        $this->assertNull($secondAccessToken);
    }

    #[Test]
    public function generateAuthorizationIdForClientCredentialsGrantReturnsSha1(): void
    {
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant(
            'oidc_test', 'ac36cGG4d2Cef1DeuevA7T1u7V4WOUI14', 'CMc4EHfyMPLw}Tua%rnyxCnrTWMuX3', 'oidc profile', ['audience' => 'https://www.example.com']
        );
        self::assertSame('c2d332337e6765c1f6876fe61c6bc63e98c1d3018ff5b56899ee54a1d1e8b1a5272b9ae9f73dc37429bccec583c3754d52bd8ef4e0f05001aa02a50e24b654a5', $authorizationId);
    }

    /**
     * @see https://github.com/flownative/flow-oauth2-client/issues/13
     */
    #[Test]
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

    #[Test]
    public function getAccessTokenReturnsNullIfNoTokenWasSet(): void
    {
        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        self::assertNull($authorization->getAccessToken());
    }

    #[Test]
    public function getAccessTokenReturnsNullIfTokenCouldNotBeDeserialized(): void
    {
        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setSerializedAccessToken('invalid json syntax');
        self::assertNull($authorization->getAccessToken());
    }

    #[Test]
    public function getScopeReturnsScope(): void
    {
        $authorization = new Authorization('3d47f0eafd6a8b49e32b55103d817b6e4ef489e7', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');
        $authorization->setScope('some-custom-scope');
        self::assertSame('some-custom-scope', $authorization->getScope());
    }

    private function createValidAccessToken(): AccessToken
    {
        return new AccessToken([
            'access_token' => Algorithms::generateRandomToken(500),
            'expires' => time() + 3600
        ]);
    }
}
