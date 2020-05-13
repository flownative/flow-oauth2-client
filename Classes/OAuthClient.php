<?php

namespace Flownative\OAuth2\Client;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\ORMException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\RequestFactory;
use Neos\Cache\Exception;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\Exception\MissingActionNameException;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Flow\Persistence\Doctrine\Query;
use Neos\Flow\Persistence\Exception\InvalidQueryException;
use Neos\Flow\Session\SessionInterface;
use Neos\Http\Factories\ServerRequestFactory;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;

/**
 * Base class for an OAuth client
 */
abstract class OAuthClient
{
    /**
     * Name of the HTTP query parameter used for passing around the authorization id
     *
     * @const string
     */
    public const AUTHORIZATION_ID_QUERY_PARAMETER_NAME = 'flownative_oauth2_authorization_id';

    /**
     * @var string
     */
    protected $serviceName;

    /**
     * @Flow\Inject
     * @var UriBuilder
     */
    protected $uriBuilder;

    /**
     * @Flow\Inject
     * @var Bootstrap
     */
    protected $bootstrap;

    /**
     * @Flow\Inject
     * @var ServerRequestFactory
     */
    protected $serverRequestFactory;

    /**
     * @Flow\InjectConfiguration(path="http.baseUri", package="Neos.Flow")
     * @var string
     */
    protected $flowBaseUriSetting;

    /**
     * @Flow\InjectConfiguration(path="garbageCollection.probability", package="Flownative.OAuth2.Client")
     * @var float
     */
    protected $garbageCollectionProbability;

    /**
     * @var Client
     */
    protected $httpClient;

    /**
     * @Flow\Inject
     * @var SessionInterface
     */
    protected $session;

    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @Flow\Inject
     * @var VariableFrontend
     */
    protected $stateCache;

    /**
     * @param string $serviceName
     */
    public function __construct(string $serviceName)
    {
        $this->serviceName = $serviceName;
    }

    /**
     * @param EntityManagerInterface $entityManager
     * @return void
     */
    public function injectEntityManager(EntityManagerInterface $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Returns the service type, i.e. a specific implementation of this client to use
     *
     * @return string For example, "FlownativeBeach", "oidc", ...
     */
    abstract public function getServiceType(): string;

    /**
     * Returns the service name, i.e. something like an instance name of the concrete implementation of this client
     *
     * @return string For example, "Github", "MySpecialService", ...
     */
    public function getServiceName(): string
    {
        return $this->serviceName;
    }

    /**
     * Returns the OAuth server's base URI
     *
     * @return string For example https://myservice.flownative.com
     */
    abstract public function getBaseUri(): string;

    /**
     * Returns the current client id (for sending authenticated requests)
     *
     * @return string The client id which is known by the OAuth server
     */
    abstract public function getClientId(): string;

    /**
     * Returns the OAuth service endpoint for the access token.
     * Override this method if needed.
     *
     * @return string
     */
    public function getAccessTokenUri(): string
    {
        return trim($this->getBaseUri(), '/') . '/oauth/token';
    }

    /**
     * Returns the OAuth service endpoint for authorizing a token.
     * Override this method if needed.
     *
     * @return string
     */
    public function getAuthorizeTokenUri(): string
    {
        return trim($this->getBaseUri(), '/') . '/oauth/token/authorize';
    }

    /**
     * Returns the OAuth service endpoint for accessing the resource owner details.
     * Override this method if needed.
     *
     * @return string
     */
    public function getResourceOwnerUri(): string
    {
        return trim($this->getBaseUri(), '/') . '/oauth/token/resource';
    }

    /**
     * Returns a factory for requests used by this OAuth client.
     *
     * You may override this method an provide a custom request factory, for example for adding
     * additional headers (e.g. User-Agent) to every request.
     *
     * @return RequestFactory
     */
    public function getRequestFactory(): RequestFactory
    {
        return new RequestFactory();
    }

    /**
     * Requests an access token using a specified grant type.
     *
     * This method is usually used using the OAuth Client Credentials Flow for machine-to-machine applications.
     * Therefore the grant type is usually Authorization::GRANT_CLIENT_CREDENTIALS. You need to specify the
     * client identifier and client secret and may optionally specify a scope.
     *
     * @param string $serviceName
     * @param string $clientId Client ID
     * @param string $clientSecret Client Secret
     * @param string $scope Scope which may consist of multiple identifiers, separated by comma
     * @param string $grantType One of the Authorization::GRAND_* constants
     * @param array $additionalParameters Additional parameters to provide in the request body while requesting the token. For example ['audience' => 'https://www.example.com/api/v1']
     * @return void
     * @throws IdentityProviderException
     */
    public function requestAccessToken(string $serviceName, string $clientId, string $clientSecret, string $scope, string $grantType, array $additionalParameters = []): void
    {
        $authorizationId = Authorization::calculateAuthorizationId($serviceName, $clientId, $scope, $grantType);
        $this->logger->info(sprintf('OAuth (%s): Retrieving access token using %s grant for client "%s" using a %s bytes long secret. (authorization id: %s)', $this->getServiceType(), $grantType, $clientId, strlen($clientSecret), $authorizationId));

        $existingAuthorization = $this->getAuthorization($authorizationId);
        if ($existingAuthorization !== null) {
            $this->entityManager->remove($existingAuthorization);
            $this->entityManager->flush();

            $this->logger->info(sprintf('OAuth (%s): Removed old OAuth token for client "%s". (authorization id: %s)', $this->getServiceType(), $clientId, $authorizationId));
        }

        $accessToken = $this->createOAuthProvider($clientId, $clientSecret)->getAccessToken($grantType, $additionalParameters);
        $authorization = $this->createNewAuthorization($serviceName, $clientId, $scope, $grantType, $accessToken);

        $this->logger->info(sprintf('OAuth (%s): Persisted new OAuth authorization %s for client "%s" with expiry time %s. (authorization id: %s)', $this->getServiceType(), $authorizationId, $clientId, $accessToken->getExpires(), $authorizationId));

        $this->entityManager->persist($authorization);
        $this->entityManager->flush();
    }

    /**
     * Start OAuth authorization with the Authorization Code flow
     *
     * @param string $clientId The client id, as provided by the OAuth server
     * @param string $clientSecret The client secret, provided by the OAuth server
     * @param UriInterface $returnToUri URI to return to when authorization is finished
     * @param string $scope Scope to request for authorization. Must be scope ids separated by space, e.g. "openid profile email"
     * @return UriInterface The URL the browser should redirect to, asking the user to authorize
     * @throws OAuthClientException
     */
    public function startAuthorization(string $clientId, string $clientSecret, UriInterface $returnToUri, string $scope): UriInterface
    {
        $authorization = new Authorization($this->getServiceType(), $clientId, Authorization::GRANT_AUTHORIZATION_CODE, $scope);
        $this->logger->info(sprintf('OAuth (%s): Starting authorization %s using client id "%s", a %s bytes long secret and scope "%s".', $this->getServiceType(), $authorization->getAuthorizationId(), $clientId, strlen($clientSecret), $scope));

        try {
            $oldAuthorization = $this->entityManager->find(Authorization::class, $authorization->getAuthorizationId());
            if ($oldAuthorization !== null) {
                $authorization = $oldAuthorization;
            }
            $authorization->setClientSecret($clientSecret);
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (ORMException $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed storing authorization in database: %s', $this->getServiceType(), $exception->getMessage()), 1568727133);
        }

        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);
        $authorizationUri = new Uri($oAuthProvider->getAuthorizationUrl(['scope' => $scope]));

        try {
            $this->stateCache->set(
                $oAuthProvider->getState(),
                [
                    'authorizationId' => $authorization->getAuthorizationId(),
                    'clientId' => $clientId,
                    'clientSecret' => $clientSecret,
                    'returnToUri' => (string)$returnToUri
                ]
            );
        } catch (Exception $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed setting cache entry for authorization: %s', $this->getServiceType(), $exception->getMessage()), 1560178858);
        }

        return $authorizationUri;
    }

    /**
     * Finish an OAuth authorization with the Authorization Code flow
     *
     * @param string $stateIdentifier The state identifier, passed back by the OAuth server as the "state" parameter
     * @param string $code The authorization code given by the OAuth server
     * @param string $scope The scope granted by the OAuth server
     * @return UriInterface The URI to return to
     * @throws OAuthClientException
     */
    public function finishAuthorization(string $stateIdentifier, string $code, string $scope): UriInterface
    {
        $stateFromCache = $this->stateCache->get($stateIdentifier);
        if (empty($stateFromCache)) {
            throw new OAuthClientException(sprintf('OAuth: Finishing authorization failed because oAuth state %s could not be retrieved from the state cache.', $stateIdentifier), 1558956494);
        }

        $authorizationId = $stateFromCache['authorizationId'];
        $clientId = $stateFromCache['clientId'];
        $clientSecret = $stateFromCache['clientSecret'];
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);

        $this->logger->info(sprintf('OAuth (%s): Finishing authorization for client "%s", authorization id "%s", using state %s.', $this->getServiceType(), $clientId, $authorizationId, $stateIdentifier));
        try {
            $authorization = $this->entityManager->find(Authorization::class, $authorizationId);
            if (!$authorization instanceof Authorization) {
                throw new OAuthClientException(sprintf('OAuth2 (%s): Finishing authorization failed because authorization %s could not be retrieved from the database.', $this->getServiceType(), $authorizationId), 1568710771);
            }

            $accessToken = $oAuthProvider->getAccessToken(Authorization::GRANT_AUTHORIZATION_CODE, ['code' => $code]);
            $this->logger->info(sprintf('OAuth (%s): Persisting OAuth token for authorization "%s" with expiry time %s.', $this->getServiceType(), $authorizationId, $accessToken->getExpires()));

            $authorization->setAccessToken($accessToken);
            $authorization->setScope($scope);

            $this->entityManager->persist($authorization);
            $this->entityManager->flush();

        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187001671, $exception);
        }

        $returnToUri = new Uri($stateFromCache['returnToUri']);
        $returnToUri = $returnToUri->withQuery(trim($returnToUri->getQuery() . '&' . self::AUTHORIZATION_ID_QUERY_PARAMETER_NAME . '=' . $authorizationId, '&'));

        $this->logger->debug(sprintf('OAuth (%s): Finished authorization "%s", $returnToUri is %s.', $this->getServiceType(), $authorizationId, $returnToUri));
        return $returnToUri;
    }

    /**
     * Refresh an OAuth authorization
     *
     * @param string $authorizationId
     * @param string $clientId
     * @param string $returnToUri
     * @return string
     * @throws OAuthClientException
     */
    public function refreshAuthorization(string $authorizationId, string $clientId, string $returnToUri): string
    {
        $authorization = $this->entityManager->find(Authorization::class, ['authorizationId' => $authorizationId]);
        if (!$authorization instanceof Authorization) {
            throw new OAuthClientException(sprintf('OAuth2: Could not refresh OAuth token because authorization %s was not found in our database.', $authorization), 1505317044316);
        }
        $oAuthProvider = $this->createOAuthProvider($clientId, $authorization->getClientSecret());

        $this->logger->info(sprintf('OAuth (%s): Refreshing authorization %s for client "%s" using a %s bytes long secret and refresh token "%s".', $this->getServiceType(), $authorizationId, $clientId, strlen($authorization->getClientSecret()), $authorization->refreshToken));

        try {
            $accessToken = $oAuthProvider->getAccessToken('refresh_token', ['refresh_token' => $authorization->refreshToken]);
            $authorization->accessToken = $accessToken->getToken();
            $authorization->expires = ($accessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires()) : null);

            $this->logger->debug(sprintf($this->getServiceType() . ': New access token is "%s", refresh token is "%s".', $authorization->accessToken, $authorization->refreshToken));

            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187196454, $exception);
        }

        return $returnToUri;
    }

    /**
     * @param string $authorizationId
     * @return Authorization|null
     */
    public function getAuthorization(string $authorizationId): ?Authorization
    {
        $oAuthToken = $this->entityManager->getRepository(Authorization::class)->find(['authorizationId' => $authorizationId]);
        return ($oAuthToken instanceof Authorization) ? $oAuthToken : null;
    }

    /**
     * Returns a prepared request to an OAuth 2.0 service provider using Bearer token authentication
     *
     * @param Authorization $authorization
     * @param string $relativeUri A relative URI of the web server, prepended by the base URI
     * @param string $method The HTTP method, for example "GET" or "POST"
     * @param array $bodyFields Associative array of body fields to send (optional)
     * @return RequestInterface
     * @throws OAuthClientException
     */
    public function getAuthenticatedRequest(Authorization $authorization, string $relativeUri, string $method = 'GET', array $bodyFields = []): RequestInterface
    {
        $accessToken = $authorization->getAccessToken();
        if ($accessToken === null) {
            throw new OAuthClientException(sprintf($this->getServiceType() . 'Failed getting an authenticated request for client ID "%s" because the authorization contained no access token', $authorization->getClientId()), 1589300319);
        }

        $oAuthProvider = $this->createOAuthProvider($authorization->getClientId(), $authorization->getClientSecret());
        return $oAuthProvider->getAuthenticatedRequest(
            $method,
            $this->getBaseUri() . $relativeUri,
            $authorization->getAccessToken(),
            [
                'headers' => [
                    'Content-Type' => 'application/json'
                ],
                'body' => ($bodyFields !== [] ? \GuzzleHttp\json_encode($bodyFields) : '')
            ]
        );
    }

    /**
     * Sends an HTTP request to an OAuth 2.0 service provider using Bearer token authentication
     *
     * @param Authorization $authorization
     * @param string $relativeUri
     * @param string $method
     * @param array $bodyFields
     * @return Response
     * @throws GuzzleException
     * @throws OAuthClientException
     */
    public function sendAuthenticatedRequest(Authorization $authorization, string $relativeUri, string $method = 'GET', array $bodyFields = []): Response
    {
        if ($this->httpClient === null) {
            $this->httpClient = new Client(['allow_redirects' => false]);
        }
        return $this->httpClient->send($this->getAuthenticatedRequest($authorization, $relativeUri, $method, $bodyFields));
    }

    /**
     * @return string
     */
    public function renderFinishAuthorizationUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getComponentContext()->getHttpRequest();
        } else {
            putenv('FLOW_REWRITEURLS=1');
            $httpRequest = $this->serverRequestFactory->createServerRequest('GET', new Uri($this->flowBaseUriSetting));
        }
        $actionRequest = ActionRequest::fromHttpRequest($httpRequest);

        $this->uriBuilder->reset();
        $this->uriBuilder->setRequest($actionRequest);
        $this->uriBuilder->setCreateAbsoluteUri(true);

        try {
            $uri = $this->uriBuilder->
            reset()->
            setCreateAbsoluteUri(true)->
            uriFor('finishAuthorization', ['serviceType' => $this->getServiceType(), 'serviceName' => $this->getServiceName()], 'OAuth', 'Flownative.OAuth2.Client');
            return $uri;
        } catch (MissingActionNameException $e) {
            return '';
        }
    }

    /**
     * Create a new OAuthToken instance
     *
     * @param string $serviceName
     * @param string $clientId
     * @param string $scope
     * @param string $grantType
     * @param AccessTokenInterface $accessToken
     * @return Authorization
     */
    protected function createNewAuthorization(string $serviceName, string $clientId, string $scope, string $grantType, AccessTokenInterface $accessToken): Authorization
    {
        $authorization = new Authorization($serviceName, $clientId, $grantType, $scope);
        $authorization->setAccessToken($accessToken);
        return $authorization;
    }

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @return GenericProvider
     */
    protected function createOAuthProvider(string $clientId, string $clientSecret): GenericProvider
    {
        return new GenericProvider([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $this->renderFinishAuthorizationUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri(),
        ], [
            'requestFactory' => $this->getRequestFactory()
        ]);
    }

    /**
     * @return void
     * @throws InvalidQueryException
     */
    protected function removeExpiredAuthorizations(): void
    {
        $query = new Query(Authorization::class);
        $authorizations = $query->matching($query->lessThan('expires', new \DateTimeImmutable()))->execute();
        foreach ($authorizations as $authorization) {
            assert($authorization instanceof Authorization);
            $this->entityManager->remove($authorization);
        }

        $this->entityManager->flush();
    }

    /**
     * Shuts down this client
     *
     * This method must not be called manually – it is invoked by Flow's object
     * management.
     *
     * @return void
     */
    public function shutdownObject(): void
    {
        $decimals = (integer)strlen(strrchr($this->garbageCollectionProbability, '.')) - 1;
        $factor = ($decimals > -1) ? $decimals * 10 : 1;
        try {
            if (random_int(1, 100 * $factor) <= ($this->garbageCollectionProbability * $factor)) {
                $this->removeExpiredAuthorizations();
            }
        } catch (InvalidQueryException $e) {
        } catch (\Exception $e) {
        }
    }
}
