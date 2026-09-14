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
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Core\RequestHandlerInterface;
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

    private ?VariableFrontend $stateCache = null; # shared by all clients of a test, like the state cache of an application

    private ?HttpClient $httpClient = null;

    private ?BrowserBinding $browserBinding = null; # the binding of the browser which runs the authorizations of a test

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
    public function startAuthorizationReturnsUriOfAuthorizationEndpointWithoutStoringAnAuthorization(): void
    {
        $client = $this->createClientForAuthorization();

        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), 'openid profile', $this->browserBinding);

        parse_str($authorizationUri->getQuery(), $queryParameters);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/token/authorize', (string)$authorizationUri->withQuery(''));
        self::assertSame('code', $queryParameters['response_type']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $queryParameters['client_id']);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/finish', $queryParameters['redirect_uri']);
        self::assertSame('openid profile', $queryParameters['scope']);
        self::assertNotEmpty($queryParameters['state']);

        self::assertSame([], $this->storedAuthorizations);
    }

    #[Test]
    public function startAuthorizationAddsAuthorizationParametersToAuthorizationUri(): void
    {
        $client = $this->createClientForAuthorization();

        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri('https://www.example.com/return'), 'openid profile', $this->browserBinding, ['login_hint' => 'jane@example.com', 'prompt' => 'login']);

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
        $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri('https://www.example.com/return'), 'openid', $this->browserBinding, [$parameterName => 'value']);
    }

    #[Test]
    public function startAuthorizationSendsPkceChallenge(): void
    {
        $client = $this->createClientForAuthorization();

        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), 'openid', $this->browserBinding);

        parse_str($authorizationUri->getQuery(), $queryParameters);
        self::assertSame('S256', $queryParameters['code_challenge_method']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $queryParameters['code_challenge']);
    }

    #[Test]
    public function startAuthorizationKeepsNoClientSecretInTheState(): void
    {
        $client = $this->createClientForAuthorization();

        $state = $this->startAuthorization($client);

        $stateEntry = $this->stateCache->get($state);
        self::assertArrayNotHasKey('clientSecret', $stateEntry);
        self::assertStringNotContainsString(OAuthTestClient::TEST_CLIENT_SECRET, serialize($stateEntry));
    }

    #[Test]
    public function finishAuthorizationStoresTokenAndReturnsReturnUriWithAuthorizationHandle(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client, 'openid profile');
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $returnUri = $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        $authorizationId = array_key_first($this->storedAuthorizations);
        parse_str($returnUri->getQuery(), $returnUriParameters);
        $authorizationHandle = $returnUriParameters[OAuthClient::generateAuthorizationIdQueryParameterName(OAuthTestClient::TEST_SERVICE_TYPE)];
        self::assertSame('https://www.example.com/return', (string)$returnUri->withQuery(''));
        self::assertSame('2', $returnUriParameters['page']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $authorizationHandle);
        self::assertStringNotContainsString($authorizationId, (string)$returnUri);
        self::assertSame('the-access-token', $this->storedAuthorizations[$authorizationId]->getAccessToken()->getToken());

        $tokenRequest = $this->transactions[0]['request'];
        parse_str((string)$tokenRequest->getBody(), $tokenRequestParameters);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/token', (string)$tokenRequest->getUri());
        self::assertSame('authorization_code', $tokenRequestParameters['grant_type']);
        self::assertSame('the-code', $tokenRequestParameters['code']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $tokenRequestParameters['client_id']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_SECRET, $tokenRequestParameters['client_secret']);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/finish', $tokenRequestParameters['redirect_uri']);
    }

    #[Test]
    public function finishAuthorizationSendsPkceVerifierOfTheAuthorizationRequest(): void
    {
        $client = $this->createClientForAuthorization();
        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), 'openid', $this->browserBinding);
        parse_str($authorizationUri->getQuery(), $queryParameters);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($queryParameters['state'], 'the-code', $this->browserCookies());

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertSame($queryParameters['code_challenge'], rtrim(strtr(base64_encode(hash('sha256', $tokenRequestParameters['code_verifier'], true)), '+/', '-_'), '='));
    }

    #[Test]
    public function authorizationWorksWithoutPkceIfTheClientDisablesIt(): void
    {
        $client = $this->createClientForAuthorization(new class('my-service-name') extends OAuthTestClient {
            protected function getPkceMethod(): ?string
            {
                return null;
            }
        });
        $authorizationUri = $client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), 'openid', $this->browserBinding);
        parse_str($authorizationUri->getQuery(), $queryParameters);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($queryParameters['state'], 'the-code', $this->browserCookies());

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertArrayNotHasKey('code_challenge', $queryParameters);
        self::assertArrayNotHasKey('code_verifier', $tokenRequestParameters);
    }

    #[Test]
    public function finishAuthorizationRejectsReturnWithoutCookieOfTheBrowserBindingAndKeepsTheState(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);

        try {
            $client->finishAuthorization($state, 'the-code', []);
            self::fail('A return without the cookie of the browser binding was accepted');
        } catch (UnknownStateException $exception) {
            self::assertSame(1789395645, $exception->getCode());
        }
        self::assertSame([], $this->transactions);

        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
        self::assertCount(1, $this->storedAuthorizations);
    }

    #[Test]
    public function finishAuthorizationRejectsReturnWithForgedSecret(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789395645);
        $client->finishAuthorization($state, 'the-code', [$this->browserBinding->cookieName => str_repeat('0', 64)]);
    }

    #[Test]
    public function finishAuthorizationRejectsReturnWithCookieOfAnotherAuthorization(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $cookieOfAnotherAuthorization = BrowserBinding::generate()->createCookie();

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789395645);
        $client->finishAuthorization($state, 'the-code', [$cookieOfAnotherAuthorization->getName() => $cookieOfAnotherAuthorization->getValue()]);
    }

    #[Test]
    public function finishAuthorizationAcceptsEachStateOnlyOnce(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'), self::createTokenResponse('another-access-token'));
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1558956494);
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationRejectsUnknownState(): void
    {
        $client = $this->createClientForAuthorization();

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1558956494);
        $client->finishAuthorization('unknown-state', 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationTurnsErrorResponseOfTokenEndpointIntoException(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(new Response(400, ['Content-Type' => 'application/json'], json_encode(['error' => 'invalid_grant'])));

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1511187001671);
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationStoresAuthorizationWithScopeAndMetadataGivenAtStart(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client, 'openid profile', [], '{"customer":"42"}');
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertCount(1, $this->storedAuthorizations);
        $authorization = reset($this->storedAuthorizations);
        self::assertSame(Authorization::GRANT_AUTHORIZATION_CODE, $authorization->getGrantType());
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $authorization->getClientId());
        self::assertSame('openid profile', $authorization->getScope());
        self::assertSame('{"customer":"42"}', $authorization->getMetadata());
    }

    #[Test]
    public function finishAuthorizationUpdatesExistingAuthorizationWithTheSameId(): void
    {
        $client = $this->createClientForAuthorization();
        $existingAuthorization = new Authorization('fixed-authorization-id', OAuthTestClient::TEST_SERVICE_TYPE, OAuthTestClient::TEST_CLIENT_ID, Authorization::GRANT_AUTHORIZATION_CODE, 'openid');
        $existingAuthorization->setMetadata('{"customer":"42"}');
        $this->storedAuthorizations['fixed-authorization-id'] = $existingAuthorization;
        $state = self::getState($client->startAuthorizationWithId('fixed-authorization-id', OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), 'openid profile', $this->browserBinding));
        $this->oAuthServer->append(self::createTokenResponse('the-new-access-token'));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertSame(['fixed-authorization-id' => $existingAuthorization], $this->storedAuthorizations);
        self::assertSame('the-new-access-token', $existingAuthorization->getAccessToken()->getToken());
        self::assertSame('openid profile', $existingAuthorization->getScope());
        self::assertSame('{"customer":"42"}', $existingAuthorization->getMetadata());
    }

    #[Test]
    public function finishAuthorizationRejectsExistingAuthorizationOfAnotherGrantType(): void
    {
        $client = $this->createClientForAuthorization();
        $this->storedAuthorizations['fixed-authorization-id'] = new Authorization('fixed-authorization-id', 'my-service-name', OAuthTestClient::TEST_CLIENT_ID, Authorization::GRANT_CLIENT_CREDENTIALS, 'read');
        $state = self::getState($client->startAuthorizationWithId('fixed-authorization-id', OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), 'openid', $this->browserBinding));
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1597312780);
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationTakesExpirationTimeOfToken(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer', 'expires_in' => 86400])));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertEqualsWithDelta(time() + 86400, reset($this->storedAuthorizations)->getExpires()->getTimestamp(), 5);
    }

    #[Test]
    public function finishAuthorizationAppliesDefaultLifetimeToTokenWithoutExpirationTime(): void
    {
        $client = $this->createClientForAuthorization();
        (new ReflectionProperty($client, 'defaultTokenLifetime'))->setValue($client, 600);
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer'])));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertEqualsWithDelta(time() + 600, reset($this->storedAuthorizations)->getExpires()->getTimestamp(), 5);
    }

    #[Test]
    public function finishAuthorizationKeepsTokenWithoutExpirationTimeIfDefaultLifetimeIsNull(): void
    {
        $client = $this->createClientForAuthorization();
        (new ReflectionProperty($client, 'defaultTokenLifetime'))->setValue($client, null);
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer'])));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertNull(reset($this->storedAuthorizations)->getExpires());
    }

    #[Test]
    public function finishAuthorizationSendsRedirectUriOfAuthorizationRequest(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $client->setFinishAuthorizationUri('https://other-host.example.com/oauth/finish');
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertSame(OAuthTestClient::TEST_BASE_URI . 'oauth/finish', $tokenRequestParameters['redirect_uri']);
    }

    #[Test]
    public function finishAuthorizationRejectsStateOfAnotherServiceNameAndKeepsIt(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $otherClient = $this->createClientForAuthorization(new OAuthTestClient('other-service-name'));

        try {
            $otherClient->finishAuthorization($state, 'the-code', $this->browserCookies());
            self::fail('The state of another service was accepted');
        } catch (UnknownStateException $exception) {
            self::assertSame(1789391698, $exception->getCode());
        }
        self::assertSame([], $this->transactions);

        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
        self::assertCount(1, $this->storedAuthorizations);
    }

    #[Test]
    public function finishAuthorizationAcceptsStateOfTheServiceWhichStartedTheAuthorization(): void
    {
        $client = $this->createClientForAuthorization(new OAuthTestClient('another-service-name'));
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertCount(1, $this->storedAuthorizations);
    }

    #[Test]
    public function finishAuthorizationRejectsStateOfAnotherServiceType(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $otherClient = $this->createClientForAuthorization(new class('my-service-name') extends OAuthTestClient {
            public static function getServiceType(): string
            {
                return 'OtherServiceType';
            }
        });

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789391698);
        $otherClient->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationRejectsStateIfTheTokenEndpointHasChanged(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $otherClient = $this->createClientForAuthorization(new class('my-service-name') extends OAuthTestClient {
            public function getAccessTokenUri(): string
            {
                return 'https://other-server.example.com/oauth/token';
            }
        });

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789391699);
        $otherClient->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationWithErrorRejectsStateOfAnotherService(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $otherClient = $this->createClientForAuthorization(new OAuthTestClient('other-service-name'));

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789391698);
        $otherClient->finishAuthorizationWithError($state, 'access_denied', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationWithErrorRejectsReturnWithoutCookieOfTheBrowserBinding(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789395645);
        $client->finishAuthorizationWithError($state, 'access_denied', []);
    }

    #[Test]
    public function finishAuthorizationRejectsStateWhichNamesNoService(): void
    {
        $client = $this->createClientForAuthorization();
        $this->stateCache->set('0123456789abcdef0123456789abcdef', ['authorizationId' => 'some-authorization', 'clientId' => OAuthTestClient::TEST_CLIENT_ID, 'clientSecret' => self::CLIENT_SECRET, 'returnToUri' => self::RETURN_URI]);

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789391698);
        $client->finishAuthorization('0123456789abcdef0123456789abcdef', 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationRejectsMalformedStateWithoutAskingTheCache(): void
    {
        $client = $this->createClientForAuthorization();

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1789386787);
        $client->finishAuthorization('<script>', 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationTakesScopeOfTokenResponse(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client, 'openid profile');
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer', 'scope' => 'openid'])));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertSame('openid', reset($this->storedAuthorizations)->getScope());
    }

    #[Test]
    public function finishAuthorizationKeepsRequestedScopeIfTokenResponseContainsNone(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client, 'openid profile');
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($state, 'the-code', $this->browserCookies());

        self::assertSame('openid profile', reset($this->storedAuthorizations)->getScope());
    }

    #[Test]
    public function finishAuthorizationTurnsTransportErrorIntoOAuthClientException(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(new ConnectException('Connection refused', new Request('POST', OAuthTestClient::TEST_BASE_URI . 'oauth/token')));

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1789386786);
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationTurnsTokenResponseWithoutJsonIntoOAuthClientException(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'text/html'], '<html lang="en"></html>'));

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1789386786);
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationAcceptsCodeWithFewerThanThreeCharacters(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->finishAuthorization($state, 'x', $this->browserCookies());

        self::assertSame('the-access-token', reset($this->storedAuthorizations)->getAccessToken()->getToken());
    }

    #[Test]
    public function authorizationLogsNeitherStateNorAuthorizationIdNorHandle(): void
    {
        $client = $this->createClientForAuthorization();
        $loggedMessages = [];
        $logger = $this->createStub(LoggerInterface::class);
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $logger->method($level)->willReturnCallback(function (string $message) use (&$loggedMessages): void {
                $loggedMessages[] = $message;
            });
        }
        (new ReflectionProperty($client, 'logger'))->setValue($client, $logger);
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $authorizationHandle = self::getAuthorizationHandle($client->finishAuthorization($state, 'the-code', $this->browserCookies()));
        $client->claimAuthorization($authorizationHandle, $this->browserCookies());

        self::assertNotSame([], $loggedMessages);
        foreach ([$state, array_key_first($this->storedAuthorizations), $authorizationHandle] as $secretValue) {
            foreach ($loggedMessages as $loggedMessage) {
                self::assertStringNotContainsString($secretValue, $loggedMessage);
            }
        }
    }

    #[Test]
    public function claimAuthorizationReturnsTheFinishedAuthorization(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));
        $authorizationHandle = self::getAuthorizationHandle($client->finishAuthorization($state, 'the-code', $this->browserCookies()));

        $authorization = $client->claimAuthorization($authorizationHandle, $this->browserCookies());

        self::assertSame(reset($this->storedAuthorizations), $authorization);
        self::assertSame('the-access-token', $authorization->getAccessToken()->getToken());
    }

    #[Test]
    public function claimAuthorizationAcceptsEachHandleOnlyOnce(): void
    {
        $client = $this->createClientForAuthorization();
        $authorizationHandle = $this->finishAuthorization($client);
        $client->claimAuthorization($authorizationHandle, $this->browserCookies());

        $this->expectException(UnknownAuthorizationHandleException::class);
        $this->expectExceptionCode(1789395647);
        $client->claimAuthorization($authorizationHandle, $this->browserCookies());
    }

    #[Test]
    public function claimAuthorizationRejectsBrowserWithoutCookieOfTheBrowserBindingAndKeepsTheHandle(): void
    {
        $client = $this->createClientForAuthorization();
        $authorizationHandle = $this->finishAuthorization($client);

        try {
            $client->claimAuthorization($authorizationHandle, []);
            self::fail('The handle was accepted without the cookie of the browser binding');
        } catch (UnknownAuthorizationHandleException $exception) {
            self::assertSame(1789395649, $exception->getCode());
        }

        self::assertSame(reset($this->storedAuthorizations), $client->claimAuthorization($authorizationHandle, $this->browserCookies()));
    }

    #[Test]
    public function claimAuthorizationRejectsHandleOfAnotherService(): void
    {
        $client = $this->createClientForAuthorization();
        $authorizationHandle = $this->finishAuthorization($client);
        $otherClient = $this->createClientForAuthorization(new OAuthTestClient('other-service-name'));

        $this->expectException(UnknownAuthorizationHandleException::class);
        $this->expectExceptionCode(1789395648);
        $otherClient->claimAuthorization($authorizationHandle, $this->browserCookies());
    }

    #[Test]
    public function claimAuthorizationRejectsMalformedHandle(): void
    {
        $client = $this->createClientForAuthorization();

        $this->expectException(UnknownAuthorizationHandleException::class);
        $this->expectExceptionCode(1789395646);
        $client->claimAuthorization('some-authorization-id', $this->browserCookies());
    }

    #[Test]
    public function claimAuthorizationRejectsHandleOfRemovedAuthorization(): void
    {
        $client = $this->createClientForAuthorization();
        $authorizationHandle = $this->finishAuthorization($client);
        $client->removeAuthorization(array_key_first($this->storedAuthorizations));

        $this->expectException(UnknownAuthorizationHandleException::class);
        $this->expectExceptionCode(1789395650);
        $client->claimAuthorization($authorizationHandle, $this->browserCookies());
    }

    #[Test]
    public function finishAuthorizationWithErrorReturnsReturnUriWithErrorCode(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);

        $returnUri = $client->finishAuthorizationWithError($state, 'access_denied', $this->browserCookies());

        parse_str($returnUri->getQuery(), $returnUriParameters);
        self::assertSame('https://www.example.com/return', (string)$returnUri->withQuery(''));
        self::assertSame('2', $returnUriParameters['page']);
        self::assertSame('access_denied', $returnUriParameters[OAuthClient::generateAuthorizationErrorQueryParameterName(OAuthTestClient::TEST_SERVICE_TYPE)]);
        self::assertArrayNotHasKey(OAuthClient::generateAuthorizationIdQueryParameterName(OAuthTestClient::TEST_SERVICE_TYPE), $returnUriParameters);
        self::assertSame([], $this->transactions);
        self::assertSame([], $this->storedAuthorizations);
    }

    #[Test]
    public function finishAuthorizationWithErrorReplacesUndefinedErrorCodes(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);

        $returnUri = $client->finishAuthorizationWithError($state, '<script>alert(1)</script>', $this->browserCookies());

        parse_str($returnUri->getQuery(), $returnUriParameters);
        self::assertSame('server_error', $returnUriParameters[OAuthClient::generateAuthorizationErrorQueryParameterName(OAuthTestClient::TEST_SERVICE_TYPE)]);
    }

    #[Test]
    public function finishAuthorizationWithErrorUsesUpTheState(): void
    {
        $client = $this->createClientForAuthorization();
        $state = $this->startAuthorization($client);
        $client->finishAuthorizationWithError($state, 'access_denied', $this->browserCookies());

        $this->expectException(UnknownStateException::class);
        $this->expectExceptionCode(1558956494);
        $client->finishAuthorization($state, 'the-code', $this->browserCookies());
    }

    #[Test]
    public function renderFinishAuthorizationUriRequiresBaseUriOutsideOfWebRequests(): void
    {
        $client = new class('my-service-name') extends OAuthClient {
            public static function getServiceType(): string
            {
                return 'test';
            }

            public function getBaseUri(): string
            {
                return OAuthTestClient::TEST_BASE_URI;
            }

            public function getClientId(): string
            {
                return OAuthTestClient::TEST_CLIENT_ID;
            }

            public function getClientSecret(string $clientId): string
            {
                return OAuthTestClient::TEST_CLIENT_SECRET;
            }
        };
        $bootstrap = $this->createStub(Bootstrap::class);
        $bootstrap->method('getActiveRequestHandler')->willReturn($this->createStub(RequestHandlerInterface::class));
        (new ReflectionProperty($client, 'bootstrap'))->setValue($client, $bootstrap);

        $this->expectException(OAuthClientException::class);
        $this->expectExceptionCode(1789386788);
        $client->renderFinishAuthorizationUri();
    }

    #[Test]
    public function requestAccessTokenSendsNoRedirectUri(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertArrayNotHasKey('redirect_uri', $tokenRequestParameters);
    }

    #[Test]
    public function requestAccessTokenStoresTokenOfClientCredentialsGrant(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read', ['audience' => 'https://api.example.com']);

        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant('my-service-name', OAuthTestClient::TEST_CLIENT_ID, 'read', ['audience' => 'https://api.example.com']);
        self::assertSame(Authorization::GRANT_CLIENT_CREDENTIALS, $this->storedAuthorizations[$authorizationId]->getGrantType());
        self::assertSame('read', $this->storedAuthorizations[$authorizationId]->getScope());
        self::assertSame('the-access-token', $this->storedAuthorizations[$authorizationId]->getAccessToken()->getToken());

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertSame('client_credentials', $tokenRequestParameters['grant_type']);
        self::assertSame(OAuthTestClient::TEST_CLIENT_ID, $tokenRequestParameters['client_id']);
        self::assertSame(self::CLIENT_SECRET, $tokenRequestParameters['client_secret']);
        self::assertSame('read', $tokenRequestParameters['scope']);
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
    public function requestAccessTokenSendsNoScopeIfScopeIsEmpty(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, '', ['audience' => 'https://api.example.com']);

        parse_str((string)$this->transactions[0]['request']->getBody(), $tokenRequestParameters);
        self::assertArrayNotHasKey('scope', $tokenRequestParameters);
    }

    #[Test]
    public function requestAccessTokenKeepsPreviousTokenIfNoNewTokenIsIssued(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(self::createTokenResponse('the-first-access-token'), new Response(401, ['Content-Type' => 'application/json'], json_encode(['error' => 'invalid_client'])));
        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');

        try {
            $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');
            self::fail('The refused token request did not throw an exception');
        } catch (IdentityProviderException) {
        }

        self::assertCount(1, $this->storedAuthorizations);
        self::assertSame('the-first-access-token', reset($this->storedAuthorizations)->getAccessToken()->getToken());
    }

    public static function reservedTokenRequestParameters(): array
    {
        $parameterNames = ['grant_type', 'client_id', 'client_secret', 'redirect_uri', 'scope', 'code', 'code_verifier', 'refresh_token'];
        return array_combine($parameterNames, array_map(static fn (string $parameterName): array => [$parameterName], $parameterNames));
    }

    #[Test]
    #[DataProvider('reservedTokenRequestParameters')]
    public function requestAccessTokenRejectsReservedAdditionalParameters(string $parameterName): void
    {
        $client = $this->createClientForAuthorization();

        try {
            $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read', [$parameterName => 'value']);
            self::fail('The reserved parameter was accepted');
        } catch (InvalidArgumentException $exception) {
            self::assertSame(1789391047, $exception->getCode());
        }
        self::assertSame([], $this->transactions);
    }

    #[Test]
    public function requestAccessTokenAppliesDefaultLifetimeToTokenWithoutExpirationTime(): void
    {
        $client = $this->createClientForAuthorization();
        (new ReflectionProperty($client, 'defaultTokenLifetime'))->setValue($client, 600);
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer'])));

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');

        self::assertEqualsWithDelta(time() + 600, reset($this->storedAuthorizations)->getExpires()->getTimestamp(), 5);
    }

    #[Test]
    public function requestAccessTokenStoresScopeGrantedByTheServer(): void
    {
        $client = $this->createClientForAuthorization();
        $this->oAuthServer->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'the-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600, 'scope' => 'read:limited'])));

        $client->requestAccessToken('my-service-name', OAuthTestClient::TEST_CLIENT_ID, self::CLIENT_SECRET, 'read');

        self::assertSame('read:limited', reset($this->storedAuthorizations)->getScope());
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

    private function createClientForAuthorization(?OAuthTestClient $client = null): OAuthTestClient
    {
        if ($this->stateCache === null) {
            $this->stateCache = new VariableFrontend('state', new TransientMemoryBackend());
            $this->stateCache->initializeObject();

            $this->oAuthServer = new MockHandler();
            $handlerStack = HandlerStack::create($this->oAuthServer);
            $handlerStack->push(Middleware::history($this->transactions));
            $this->httpClient = new HttpClient(['handler' => $handlerStack]);

            $this->browserBinding = BrowserBinding::generate();
        }

        $client ??= new OAuthTestClient('my-service-name');
        $client->injectEntityManager($this->createInMemoryEntityManager());
        $client->setHttpClient($this->httpClient);
        (new ReflectionProperty($client, 'stateCache'))->setValue($client, $this->stateCache);
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

    /**
     * Returns the state of an authorization which the browser of the test started
     */
    private function startAuthorization(OAuthTestClient $client, string $scope = 'openid', array $authorizationParameters = [], ?string $metadata = null): string
    {
        return self::getState($client->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri(self::RETURN_URI), $scope, $this->browserBinding, $authorizationParameters, $metadata));
    }

    /**
     * Returns the handle of an authorization which the browser of the test started and finished
     */
    private function finishAuthorization(OAuthTestClient $client): string
    {
        $state = $this->startAuthorization($client);
        $this->oAuthServer->append(self::createTokenResponse('the-access-token'));
        return self::getAuthorizationHandle($client->finishAuthorization($state, 'the-code', $this->browserCookies()));
    }

    private function browserCookies(): array
    {
        $cookie = $this->browserBinding->createCookie();
        return [$cookie->getName() => $cookie->getValue()];
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

    private static function getAuthorizationHandle(UriInterface $returnUri): string
    {
        parse_str($returnUri->getQuery(), $returnUriParameters);
        return $returnUriParameters[OAuthClient::generateAuthorizationIdQueryParameterName(OAuthTestClient::TEST_SERVICE_TYPE)];
    }
}
