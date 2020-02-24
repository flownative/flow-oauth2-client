<?php

namespace Flownative\OAuth2\Client;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\DBAL\LockMode;
use Doctrine\ORM\EntityManagerInterface as DoctrineEntityManagerInterface;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Doctrine\ORM\TransactionRequiredException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\RequestFactory;
use Neos\Cache\Exception;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\Log\PsrSystemLoggerInterface;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\Exception\MissingActionNameException;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Flow\Persistence\Doctrine\Query;
use Neos\Flow\Persistence\Exception\InvalidQueryException;
use Neos\Flow\Session\SessionInterface;
use Psr\Http\Message\RequestInterface;

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
     * @var DoctrineEntityManagerInterface
     */
    protected $entityManager;

    /**
     * @Flow\Inject
     * @var PsrSystemLoggerInterface
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
     * @param DoctrineEntityManagerInterface $entityManager
     * @return void
     */
    public function injectEntityManager(DoctrineEntityManagerInterface $entityManager): void
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
     * Add credentials for a Client Credentials Grant
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $scope
     * @return void
     * @throws IdentityProviderException
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws TransactionRequiredException
     */
    public function getAccessToken(string $grant, string $clientId, string $clientSecret, string $scope = ''): void
    {
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);

        // FIXME
        $authorizationId = 'foobarbaz';

        try {
            $this->logger->info(sprintf('OAuth (%s): Retrieving client credentials for client "%s" using a %s bytes long secret.', $this->getServiceType(), $clientId, strlen($clientSecret)), LogEnvironment::fromMethodName(__METHOD__));

            $oldOAuthToken = $this->getAuthorization($authorizationId);
            if ($oldOAuthToken !== null) {
                $this->entityManager->remove($oldOAuthToken);
                $this->entityManager->flush();

                $this->logger->info(sprintf('OAuth (%s):  Removed old OAuth token for client "%s".', $this->getServiceType(), $clientId), LogEnvironment::fromMethodName(__METHOD__));
            }

            $accessToken = $oAuthProvider->getAccessToken('client_credentials');
            $authorization = $this->createNewAuthorization($clientId, $clientSecret, 'client_credentials', $accessToken, $scope);

            $this->logger->info(sprintf('OAuth (%s): Persisted new OAuth authorization %s for client "%s" with expiry time %s.', $this->getServiceType(), $authorizationId, $clientId, $accessToken->getExpires()), LogEnvironment::fromMethodName(__METHOD__));

            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (IdentityProviderException $e) {
            throw $e;
        }
    }

    /**
     * Start OAuth authorization with the Authorization Code flow
     *
     * @param string $clientId The client id, as provided by the OAuth server
     * @param string $clientSecret The client secret, provided by the OAuth server
     * @param Uri $returnToUri URI to return to when authorization is finished
     * @param string $scope Scope to request for authorization. Must be scope ids separated by space, e.g. "openid profile email"
     * @return Uri The URL the browser should redirect to, asking the user to authorize
     * @throws OAuthClientException
     */
    public function startAuthorization(string $clientId, string $clientSecret, Uri $returnToUri, string $scope): Uri
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
     * @return Uri The URI to return to
     * @throws OAuthClientException
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws TransactionRequiredException
     */
    public function finishAuthorization(string $stateIdentifier, string $code): Uri
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

            $accessToken = $oAuthProvider->getAccessToken('authorization_code', ['code' => $code]);
            $this->logger->info(sprintf('OAuth (%s): Persisting OAuth token for authorization "%s" with expiry time %s.', $this->getServiceType(), $authorizationId, $accessToken->getExpires()));

            $authorization->setAccessToken($accessToken);

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
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws TransactionRequiredException
     */
    public function refreshAuthorization(string $authorizationId, string $clientId, string $returnToUri): string
    {
        $authorization = $this->entityManager->find(Authorization::class, ['authorizationId' => $authorizationId]);
        if (!$authorization instanceof Authorization) {
            throw new OAuthClientException(sprintf('OAuth2: Could not refresh OAuth token because authorization %s was not found in our database.', $authorization), 1505317044316);
        }
        $oAuthProvider = $this->createOAuthProvider($clientId, $authorization->clientSecret);

        $this->logger->info(sprintf('OAuth (%s): Refreshing authorization %s for client "%s" using a %s bytes long secret and refresh token "%s".', $this->getServiceType(), $authorizationId, $clientId, strlen($authorization->clientSecret), $authorization->refreshToken), LogEnvironment::fromMethodName(__METHOD__));

        try {
            $accessToken = $oAuthProvider->getAccessToken('refresh_token', ['refresh_token' => $authorization->refreshToken]);
            $authorization->accessToken = $accessToken->getToken();
            $authorization->expires = ($accessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires()) : null);

            $this->logger->debug(sprintf($this->getServiceType() . ': New access token is "%s", refresh token is "%s".', $authorization->accessToken, $authorization->refreshToken), LogEnvironment::fromMethodName(__METHOD__));

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
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws TransactionRequiredException
     */
    public function getAuthorization(string $authorizationId): ?Authorization
    {
        $oAuthToken = $this->entityManager->find(Authorization::class, ['authorizationId' => $authorizationId], LockMode::NONE);
        return ($oAuthToken instanceof Authorization) ? $oAuthToken : null;
    }

    /**
     * Returns a prepared request which provides the needed header for OAuth authentication
     *
     * @param string $relativeUri A relative URI of the web server, prepended by the base URI
     * @param string $method The HTTP method, for example "GET" or "POST"
     * @param array $bodyFields Associative array of body fields to send (optional)
     * @return RequestInterface
     * @throws IdentityProviderException
     * @throws OAuthClientException
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws TransactionRequiredException
     */
    public function getAuthenticatedRequest(string $relativeUri, string $method = 'GET', array $bodyFields = []): RequestInterface
    {
        $oAuthToken = $this->getAuthorization();
        if (!$oAuthToken instanceof Authorization) {
            throw new OAuthClientException('No OAuthToken found.', 1505321014388);
        }

        $oAuthProvider = $this->createOAuthProvider($oAuthToken->clientId, $oAuthToken->clientSecret);

        if ($oAuthToken->expires < new \DateTimeImmutable()) {
            switch ($oAuthToken->grantType) {
                case 'authorization_code':
                    $this->refreshAuthorization($oAuthToken->clientId, '');
                    $oAuthToken = $this->getAuthorization();
                break;
                case 'client_credentials':
                    try {
                        $newAccessToken = $oAuthProvider->getAccessToken('client_credentials');
                    } catch (IdentityProviderException $exception) {
                        $this->logger->error(sprintf($this->getServiceType() . 'Failed retrieving new OAuth access token for client "%s" (client credentials grant): %s', $oAuthToken->clientId, $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
                        throw $exception;
                    }

                    $oAuthToken->accessToken = $newAccessToken->getToken();
                    $oAuthToken->expires = ($newAccessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $newAccessToken->getExpires()) : null);

                    $this->logger->info(sprintf('OAuth (%s): Persisted new OAuth token for client "%s" with expiry time %s.', $this->getServiceType(), $oAuthToken->clientId, $newAccessToken->getExpires()), LogEnvironment::fromMethodName(__METHOD__));

                    $this->entityManager->persist($oAuthToken);
                    $this->entityManager->flush();
                break;
            }
        }

        $body = ($bodyFields !== [] ? \GuzzleHttp\json_encode($bodyFields) : '');

        return $oAuthProvider->getAuthenticatedRequest(
            $method,
            $this->getBaseUri() . $relativeUri,
            $oAuthToken->accessToken,
            [
                'headers' => [
                    'Content-Type' => 'application/json'
                ],
                'body' => $body
            ]
        );
    }

    /**
     * @param string $relativeUri
     * @param string $method
     * @param array $bodyFields
     * @return Response
     * @throws IdentityProviderException
     * @throws OAuthClientException
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws TransactionRequiredException
     * @throws GuzzleException
     */
    public function sendAuthenticatedRequest(string $relativeUri, string $method = 'GET', array $bodyFields = []): Response
    {
        if ($this->httpClient === null) {
            $this->httpClient = new Client();
        }
        // FIXME
#        return $this->httpClient->send($this->getAuthenticatedRequest($relativeUri, $method, $bodyFields));
    }

    /**
     * @return string
     * @throws
     */
    public function renderFinishAuthorizationUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getHttpRequest();
        } else {
            putenv('FLOW_REWRITEURLS=1');
            $httpRequest = Request::createFromEnvironment();
            $httpRequest->setBaseUri(new Uri($this->flowBaseUriSetting));
        }
        $actionRequest = new ActionRequest($httpRequest);

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
     * @param string $clientId
     * @param string $clientSecret
     * @param string $grantType
     * @param AccessTokenInterface $accessToken
     * @param string $scope
     * @return Authorization
     */
    protected function createNewAuthorization(string $clientId, string $clientSecret, string $grantType, AccessTokenInterface $accessToken, string $scope): Authorization
    {
        $authorization = new Authorization($this->getServiceType(), $clientId, $clientSecret, $grantType, $scope);
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
     * @throws ORMException
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
     * @throws InvalidQueryException
     * @throws ORMException
     */
    public function shutdownObject(): void
    {
        $decimals = (integer)strlen(strrchr($this->garbageCollectionProbability, '.')) - 1;
        $factor = ($decimals > -1) ? $decimals * 10 : 1;
        if (rand(1, 100 * $factor) <= ($this->garbageCollectionProbability * $factor)) {
            $this->removeExpiredAuthorizations();
        }
    }
}
