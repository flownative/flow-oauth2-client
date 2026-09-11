<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

require_once('Fixtures/OAuthTestClient.php');

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ObjectRepository;
use Flownative\OAuth2\Client\Tests\Unit\Fixtures\OAuthTestClient;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use ReflectionProperty;

class OAuthClientTest extends TestCase
{
    #[Test]
    public function constructorSetsServiceName(): void
    {
        $client = new OAuthTestClient('my-service-name');
        self::assertSame('my-service-name', $client->getServiceName());
    }

    #[Test]
    public function baseUriIsUsedForConstructingEndpointUris(): void
    {
        $client = new OAuthTestClient('my-service-name');

        $actualUri = $client->getAccessTokenUri();
        $expectedUri = OAuthTestClient::TEST_BASE_URI . 'oauth/token';
        self::assertSame($expectedUri, $actualUri);

        $actualUri = $client->getAuthorizeTokenUri();
        $expectedUri = OAuthTestClient::TEST_BASE_URI . 'oauth/token/authorize';
        self::assertSame($expectedUri, $actualUri);

        $actualUri = $client->getResourceOwnerUri();
        $expectedUri = OAuthTestClient::TEST_BASE_URI . 'oauth/token/resource';
        self::assertSame($expectedUri, $actualUri);
    }

    #[Test]
    public function generateAuthorizationIdQueryParameterName(): void
    {
       self::assertSame('flownative_oauth2_authorization_id_test-service-type', OAuthTestClient::generateAuthorizationIdQueryParameterName('test-service-type'));
    }

    #[Test]
    public function getAuthorizationFetchesAuthorizationFromRepository(): void
    {
        $authorizationId = '3d47f0eafd6a8b49e32b55103d817b6e4ef489e7';
        $expectedAuthorization = new Authorization($authorizationId, 'service', 'clientId',Authorization::GRANT_AUTHORIZATION_CODE, 'profile');

        $mockRepository = $this->createStub(ObjectRepository::class);
        $mockRepository->method('find')->willReturnMap([[['authorizationId' => $authorizationId], $expectedAuthorization]]);

        $mockEntityManager = $this->createStub(EntityManagerInterface::class);
        $mockEntityManager->method('getRepository')->willReturnMap([[Authorization::class, $mockRepository]]);

        $client = new OAuthTestClient('my-service-name');
        $client->injectEntityManager($mockEntityManager);

        $actualAuthorization = $client->getAuthorization($authorizationId);
        self::assertSame($expectedAuthorization, $actualAuthorization);
    }

    #[Test]
    public function startAuthorizationAddsAuthorizationParametersToAuthorizationUri(): void
    {
        $client = $this->createClientForAuthorization();

        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, 'my-client-secret', new Uri('https://www.example.com/return'), 'openid profile', ['login_hint' => 'jane@example.com', 'prompt' => 'login']);

        parse_str($authorizationUri->getQuery(), $queryParameters);
        self::assertSame('jane@example.com', $queryParameters['login_hint']);
        self::assertSame('login', $queryParameters['prompt']);
        self::assertSame('openid profile', $queryParameters['scope']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $queryParameters['client_id']);
    }

    public static function reservedAuthorizationParameters(): array
    {
        $parameterNames = ['client_id', 'client_secret', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'state', 'code_challenge', 'code_challenge_method', 'request', 'request_uri'];
        return array_combine($parameterNames, array_map(static fn (string $parameterName): array => [$parameterName], $parameterNames));
    }

    #[Test]
    #[DataProvider('reservedAuthorizationParameters')]
    public function startAuthorizationRejectsReservedAuthorizationParameters(string $parameterName): void
    {
        $client = $this->createClientForAuthorization();
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects($this->never())->method('persist');
        $client->injectEntityManager($entityManager);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1789131855);
        $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, 'my-client-secret', new Uri('https://www.example.com/return'), 'openid', [$parameterName => 'value']);
    }

    private function createClientForAuthorization(): OAuthTestClient
    {
        $stateCache = new VariableFrontend('state', new TransientMemoryBackend());
        $stateCache->initializeObject();

        $client = new OAuthTestClient('my-service-name');
        $client->injectEntityManager($this->createStub(EntityManagerInterface::class));
        (new ReflectionProperty($client, 'stateCache'))->setValue($client, $stateCache);
        (new ReflectionProperty($client, 'logger'))->setValue($client, $this->createStub(LoggerInterface::class));
        return $client;
    }
}
