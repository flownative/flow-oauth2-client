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

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ObjectRepository;
use Flownative\OAuth2\Client\Tests\Unit\Fixtures\OAuthTestClient;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;
use ReflectionProperty;
use RuntimeException;

class OAuthClientTest extends TestCase
{
    private const string CLIENT_SECRET = 'my-client-secret';
    private const string RETURN_URI = 'https://www.example.com/return?page=2';

    private array $storedAuthorizations = []; # authorizations persisted through the entity manager stub, by authorization id

    private array $transactions = []; # requests sent to the OAuth server, recorded by Guzzle's history middleware

    private MockHandler $oAuthServer;

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
    public function startAuthorizationStoresAuthorizationAndReturnsUriOfAuthorizationEndpoint(): void
    {
        $client = $this->createClientForAuthorization();

        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, new Uri(self::RETURN_URI), 'openid profile');

        parse_str($authorizationUri->getQuery(), $queryParameters);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/token/authorize', (string)$authorizationUri->withQuery(''));
        self::assertSame('code', $queryParameters['response_type']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $queryParameters['client_id']);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/finish', $queryParameters['redirect_uri']);
        self::assertSame('openid profile', $queryParameters['scope']);
        self::assertNotEmpty($queryParameters['state']);

        self::assertCount(1, $this->storedAuthorizations);
        $authorization = reset($this->storedAuthorizations);
        self::assertSame(Authorization::GRANT_AUTHORIZATION_CODE, $authorization->getGrantType());
        self::assertSame('openid profile', $authorization->getScope());
        self::assertNull($authorization->getAccessToken());
    }

    #[Test]
    public function startAuthorizationAddsAuthorizationParametersToAuthorizationUri(): void
    {
        $client = $this->createClientForAuthorization();

        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, new Uri('https://www.example.com/return'), 'openid profile', ['login_hint' => 'jane@example.com', 'prompt' => 'login']);

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
        $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, new Uri('https://www.example.com/return'), 'openid', [$parameterName => 'value']);
    }

    #[Test]
    public function finishAuthorizationStoresTokenAndReturnsReturnUriWithAuthorizationId(): void
    {
        $client = $this->createClientForAuthorization();
        $state = self::getState($client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, new Uri(self::RETURN_URI), 'openid profile'));
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $returnUri = $client->finishAuthorization($state, 'the-code', '');

        $authorizationId = array_key_first($this->storedAuthorizations);
        parse_str($returnUri->getQuery(), $returnUriParameters);
        self::assertSame('https://www.example.com/return', (string)$returnUri->withQuery(''));
        self::assertSame('2', $returnUriParameters['page']);
        self::assertSame($authorizationId, $returnUriParameters[OAuthClient::generateAuthorizationIdQueryParameterName(OAuthTestClient::TEST_SERVICE_TYPE)]);
        self::assertSame('the-access-token', $this->storedAuthorizations[$authorizationId]->getAccessToken()->getToken());

        $tokenRequest = $this->transactions[0]['request'];
        parse_str((string)$tokenRequest->getBody(), $tokenRequestParameters);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/token', (string)$tokenRequest->getUri());
        self::assertSame('authorization_code', $tokenRequestParameters['grant_type']);
        self::assertSame('the-code', $tokenRequestParameters['code']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $tokenRequestParameters['client_id']);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/finish', $tokenRequestParameters['redirect_uri']);
    }

    #[Test]
    public function finishAuthorizationAcceptsEachStateOnlyOnce(): void
    {
        $client = $this->createClientForAuthorization();
        $state = self::getState($client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, new Uri(self::RETURN_URI), 'openid'));
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'), self::createTokenResponse('another-access-token'));
        $client->finishAuthorization($state, 'the-code', '');

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1558956494);
        $client->finishAuthorization($state, 'the-code', '');
    }

    #[Test]
    public function finishAuthorizationRejectsUnknownState(): void
    {
        $client = $this->createClientForAuthorization();

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1558956494);
        $client->finishAuthorization('unknown-state', 'the-code', '');
    }

    #[Test]
    public function finishAuthorizationTurnsErrorResponseOfTokenEndpointIntoException(): void
    {
        $client = $this->createClientForAuthorization();
        $state = self::getState($client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, new Uri(self::RETURN_URI), 'openid'));
        $this->oAuthServer->append(new Response(400, ['Content-Type' => 'application/json'], json_encode(['error' => 'invalid_grant'])));

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1511187001671);
        $client->finishAuthorization($state, 'the-code', '');
    }

    #[Test]
    public function requestAccessTokenStoresTokenOfClientCredentialsGrant(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read', ['audience' => 'https://api.example.com']);

        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read', ['audience' => 'https://api.example.com']);
        self::assertSame(Authorization::GRANT_CLIENT_CREDENTIALS, $this->storedAuthorizations[$authorizationId]->getGrantType());
        self::assertSame('the-access-token', $this->storedAuthorizations[$authorizationId]->getAccessToken()->getToken());

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertSame('client_credentials', $tokenRequestParameters['grant_type']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $tokenRequestParameters['client_id']);
        self::assertSame('https://api.example.com', $tokenRequestParameters['audience']);
    }

    #[Test]
    public function requestAccessTokenReplacesPreviouslyStoredToken(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(self::createTokenResponse('the-first-access-token'), self::createTokenResponse('the-second-access-token'));
        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');

        self::assertCount(1, $this->storedAuthorizations);
        self::assertSame('the-second-access-token', reset($this->storedAuthorizations)->getAccessToken()->getToken());
    }

    #[Test]
    public function removeAuthorizationRemovesStoredAuthorization(): void
    {
        $client = $this->createClientForAuthorization();
        $this->storedAuthorizations['some-authorization'] = new Authorization('some-authorization', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');

        $client->removeAuthorization('some-authorization');
        $client->removeAuthorization('unknown-authorization');

        self::assertSame([], $this->storedAuthorizations);
    }

    #[Test]
    public function setAuthorizationMetadataStoresMetadataOfAuthorization(): void
    {
        $client = $this->createClientForAuthorization();
        $this->storedAuthorizations['some-authorization'] = new Authorization('some-authorization', 'service', 'clientId', Authorization::GRANT_AUTHORIZATION_CODE, '');

        $client->setAuthorizationMetadata('some-authorization', '{"some":"metadata"}');

        self::assertSame('{"some":"metadata"}', $this->storedAuthorizations['some-authorization']->getMetadata());
    }

    #[Test]
    public function setAuthorizationMetadataRejectsUnknownAuthorization(): void
    {
        $client = $this->createClientForAuthorization();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionCode(1631821719);
        $client->setAuthorizationMetadata('unknown-authorization', '{}');
    }

    private function createClientForAuthorization(): OAuthTestClient
    {
        $stateCache = new VariableFrontend('state', new TransientMemoryBackend());
        $stateCache->initializeObject();

        $this->oAuthServer = new MockHandler();
        $handlerStack = HandlerStack::create($this->oAuthServer);
        $handlerStack->push(Middleware::history($this->transactions));

        $client = new OAuthTestClient('my-service-name');
        $client->injectEntityManager($this->createInMemoryEntityManager());
        $client->setHttpClient(new HttpClient(['handler' => $handlerStack]));
        (new ReflectionProperty($client, 'stateCache'))->setValue($client, $stateCache);
        (new ReflectionProperty($client, 'logger'))->setValue($client, $this->createStub(LoggerInterface::class));
        return $client;
    }

    private function createInMemoryEntityManager(): EntityManagerInterface
    {
        $repository = $this->createStub(ObjectRepository::class);
        $repository->method('find')->willReturnCallback(fn (array $criteria): ?Authorization => $this->storedAuthorizations[$criteria['authorizationId']] ?? null);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($repository);
        $entityManager->method('find')->willReturnCallback(fn (string $className, mixed $id): ?Authorization => $this->storedAuthorizations[is_array($id) ? $id['authorizationId'] : $id] ?? null);
        $entityManager->method('persist')->willReturnCallback(function (Authorization $authorization): void {
            $this->storedAuthorizations[$authorization->getAuthorizationId()] = $authorization;
        });
        $entityManager->method('remove')->willReturnCallback(function (Authorization $authorization): void {
            unset($this->storedAuthorizations[$authorization->getAuthorizationId()]);
        });
        return $entityManager;
    }

    private static function createTokenResponse(string $accessToken): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => $accessToken, 'token_type' => 'Bearer', 'expires_in' => 3600]));
    }

    private static function getState(UriInterface $authorizationUri): string
    {
        parse_str($authorizationUri->getQuery(), $queryParameters);
        return $queryParameters['state'];
    }
}
