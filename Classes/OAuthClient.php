<?php

namespace Flownative\OAuth2\Client;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\ORM\EntityManager as DoctrineEntityManager;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\RequestFactory;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Http\Request;
use Neos\Flow\Http\Uri;
use Neos\Flow\Log\SystemLoggerInterface;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Flow\Persistence\Doctrine\Query;
use Neos\Flow\Session\SessionInterface;

abstract class OAuthClient
{
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
     * @var Client
     */
    protected $httpClient;

    /**
     * @Flow\Inject
     * @var SessionInterface
     */
    protected $session;

    /**
     * @var DoctrineEntityManager
     */
    protected $entityManager;

    /**
     * @Flow\Inject
     * @var SystemLoggerInterface
     */
    protected $logger;

    /**
     * @param DoctrineObjectManager $entityManager
     * @return void
     */
    public function injectEntityManager(DoctrineObjectManager $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Returns the service name
     *
     * @return string For example, "FlownativeBeach", "Paypal", "Stripe", "Twitter"
     */
    abstract static public function getServiceName(): string;

    /**
     * Returns the OAuth server's base URI
     *
     * @return string For example https://myservice.flownative.com
     */
    abstract public function getBaseUri(): string;

    /**
     * Returns the current client id (for sending authenticated requests)
     *
     * @return string The client id which is known by the OAuth2 server
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
        return $this->getBaseUri() . '/oauth/token';
    }

    /**
     * Returns the OAuth service endpoint for authorizing a token.
     * Override this method if needed.
     *
     * @return string
     */
    public function getAuthorizeTokenUri(): string
    {
        return $this->getBaseUri() . '/oauth/token/authorize';
    }

    /**
     * Returns the OAuth service endpoint for accessing the resource owner details.
     * Override this method if needed.
     *
     * @return string
     */
    public function getResourceOwnerUri(): string
    {
        return $this->getBaseUri() . '/oauth/token/resource';
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
     * @throws IdentityProviderException
     */
    public function addClientCredentials(string $clientId, string $clientSecret, string $scope = '')
    {
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);

        try {
            $this->logger->log(sprintf(static::getServiceName() . 'Setting client credentials for client "%s" using a %s bytes long secret.', $clientId, strlen($clientSecret)), LOG_INFO);

            $oldOAuthToken = $this->getOAuthToken();
            if ($oldOAuthToken !== null) {
                $this->entityManager->remove($oldOAuthToken);
                $this->entityManager->flush();

                $this->logger->log(sprintf(static::getServiceName() . 'Removed old OAuth token for client "%s".', $clientId), LOG_INFO);
            }

            $accessToken = $oAuthProvider->getAccessToken('client_credentials');
            $oAuthToken = $this->createNewOAuthToken($clientId, $clientSecret, 'client_credentials', $accessToken, $scope);

            $this->logger->log(sprintf(static::getServiceName() . 'Persisted new OAuth token for client "%s" with expiry time %s.', $clientId, $accessToken->getExpires()), LOG_INFO);

            $this->entityManager->persist($oAuthToken);
            $this->entityManager->flush();
        } catch (IdentityProviderException $e) {
            throw $e;
        }
    }

    /**
     * Start OAuth authorization
     *
     * @param string $clientId The client id, as provided by the OAuth server
     * @param string $clientSecret The client secret, provided by the OAuth server
     * @param string $returnToUri URI to return to when authorization is finished
     * @return string The URL the browser should redirect to, asking the user to authorize
     */
    public function startAuthorization(string $clientId, string $clientSecret, string $returnToUri)
    {
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);
        $authorizationUri = $oAuthProvider->getAuthorizationUrl();

        $this->logger->log(sprintf(static::getServiceName() . ': Starting authorization for client "%s" using a %s bytes long secret, returning to "%s".', $clientId, strlen($clientSecret), $returnToUri), LOG_INFO);

        $oldOAuthToken = $this->getOAuthToken();
        if ($oldOAuthToken !== null) {
            $this->entityManager->remove($oldOAuthToken);
            $this->entityManager->flush();

            $this->logger->log(sprintf(static::getServiceName() . ': Removed old OAuth token for client "%s".', $oldOAuthToken->clientId), LOG_INFO);
        }

        $this->session->putData(static::getServiceName() . '.oAuthClientId', $clientId);
        $this->session->putData(static::getServiceName() . '.oAuthClientSecret', $clientSecret);
        $this->session->putData(static::getServiceName() . '.oAuthState', $oAuthProvider->getState());
        $this->session->putData(static::getServiceName() . '.returnToUri', $returnToUri);

        return $authorizationUri;
    }

    /**
     * Finish an OAuth authorization
     *
     * @param string $code The authorization code given by the OAuth server
     * @param string $state The authorization state given by the OAuth server
     * @param string $scope The scope for the granted authorization (syntax varies depending on the service)
     * @return string The URI to return to
     * @throws OAuthClientException
     */
    public function finishAuthorization(string $code, string $state, string $scope)
    {
        $stateFromSession = $this->session->getData(static::getServiceName() . '.oAuthState');
        if (empty($state) || $stateFromSession !== $state) {
            throw new OAuthClientException('Invalid oAuth2 state.', 1505313625652);
        }

        $clientId = (string)$this->session->getData(static::getServiceName() . '.oAuthClientId');
        $clientSecret = (string)$this->session->getData(static::getServiceName() . '.oAuthClientSecret');
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);

        try {
            $this->logger->log(sprintf(static::getServiceName() . ': Finishing authorization for client "%s" using a %s bytes long secret.', $clientId, strlen($clientSecret)), LOG_INFO);

            $oldOAuthToken = $this->entityManager->find(OAuthToken::class, ['clientId' => $clientId, 'serviceName' => static::getServiceName()]);
            if ($oldOAuthToken !== null) {
                $this->entityManager->remove($oldOAuthToken);
                $this->entityManager->flush();

                $this->logger->log(sprintf(static::getServiceName() . ': Removed old OAuth token for client "%s".', $clientId), LOG_INFO);
            }

            $accessToken = $oAuthProvider->getAccessToken('authorization_code', ['code' => $code]);
            $oAuthToken = $this->createNewOAuthToken($clientId, $clientSecret, 'authorization_code', $accessToken, $scope);

            $this->logger->log(sprintf(static::getServiceName() . ': Persisted new OAuth token for client "%s" with expiry time %s.', $clientId, $accessToken->getExpires()), LOG_INFO);

            $this->entityManager->persist($oAuthToken);
            $this->entityManager->flush();
        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187001671, $exception);
        }

        return (string)$this->session->getData(static::getServiceName() . '.returnToUri');
    }

    /**
     * Refresh an OAuth authorization
     *
     * @param string $clientId
     * @param string $returnToUri
     * @return string
     * @throws IdentityProviderException
     * @throws OAuthClientException
     */
    public function refreshAuthorization(string $clientId, string $returnToUri): string
    {
        $oAuthToken = $this->entityManager->find(OAuthToken::class, ['clientId' => $clientId, 'serviceName' => static::getServiceName()]);
        if (!$oAuthToken instanceof OAuthToken) {
            throw new OAuthClientException(static::getServiceName() . ': Could not refresh OAuth2 token because it was not found in our database.', 1505317044316);
        }
        $oAuthProvider = $this->createOAuthProvider($clientId, $oAuthToken->clientSecret);

        $this->logger->log(sprintf(static::getServiceName() . ': Refreshing authorization for client "%s" using a %s bytes long secret and refresh token "%s".', $clientId, strlen($oAuthToken->clientSecret), $oAuthToken->refreshToken), LOG_INFO);

        try {
            $accessToken = $oAuthProvider->getAccessToken('refresh_token', ['refresh_token' => $oAuthToken->refreshToken]);
            $oAuthToken->accessToken = $accessToken->getToken();
            $oAuthToken->expires = ($accessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires()) : null);

            $this->logger->log(sprintf(static::getServiceName() . ': New access token is "%s", refresh token is "%s".', $oAuthToken->accessToken, $oAuthToken->refreshToken), LOG_DEBUG);

            $this->entityManager->persist($oAuthToken);
            $this->entityManager->flush();
        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187196454, $exception);
        }

        return $returnToUri;
    }

    /**
     * @return OAuthToken|null
     */
    public function getOAuthToken(): ?OAuthToken
    {
        $oAuthToken = $this->entityManager->find(OAuthToken::class, ['clientId' => $this->getClientId(), 'serviceName' => static::getServiceName()]);
        return ($oAuthToken instanceof OAuthToken) ? $oAuthToken : null;
    }

    /**
     * Returns a prepared request which provides the needed header for OAuth authentication
     *
     * @param string $relativeUri A relative URI of the web server, prepended by the base URI
     * @param string $method The HTTP method, for example "GET" or "POST"
     * @param array $bodyFields Associative array of body fields to send (optional)
     * @return \Psr\Http\Message\RequestInterface
     * @throws OAuthClientException
     */
    public function getAuthenticatedRequest(string $relativeUri, string $method = 'GET', array $bodyFields = [])
    {
        $oAuthToken = $this->getOAuthToken();
        if (!$oAuthToken instanceof OAuthToken) {
            throw new OAuthClientException('No OAuthToken found.', 1505321014388);
        }

        $oAuthProvider = $this->createOAuthProvider($oAuthToken->clientId, $oAuthToken->clientSecret);

        if ($oAuthToken->expires < new \DateTimeImmutable()) {
            switch($oAuthToken->grantType) {
                case 'authorization_code':
                    $this->refreshAuthorization($oAuthToken->clientId, '');
                    $oAuthToken = $this->getOAuthToken();
                break;
                case 'client_credentials':
                    try {
                        $newAccessToken = $oAuthProvider->getAccessToken('client_credentials');
                    } catch(IdentityProviderException $exception) {
                        $this->logger->log(sprintf(static::getServiceName() . 'Failed retrieving new OAuth access token for client "%s" (client credentials grant): %s', $oAuthToken->clientId, $exception->getMessage()), LOG_ERR);
                        throw $exception;
                    }

                    $oAuthToken->accessToken = $newAccessToken->getToken();
                    $oAuthToken->expires = ($newAccessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $newAccessToken->getExpires()) : null);

                    $this->logger->log(sprintf(static::getServiceName() . 'Persisted new OAuth token for client "%s" with expiry time %s.', $oAuthToken->clientId, $newAccessToken->getExpires()), LOG_INFO);

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
     */
    public function sendAuthenticatedRequest(string $relativeUri, string $method = 'GET', array $bodyFields = []): Response
    {
        if ($this->httpClient === null) {
            $this->httpClient = new Client();
        }
        return $this->httpClient->send($this->getAuthenticatedRequest($relativeUri, $method, $bodyFields));
    }

    /**
     * @return string
     */
    public function renderRedirectUri(): string
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

        return $this->uriBuilder->uriFor('finishAuthorization', ['serviceName' => static::getServiceName()], 'OAuth', 'Flownative.OAuth2.Client');
    }

    /**
     * Create a new OAuthToken instance
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $grantType
     * @param AccessToken $accessToken
     * @param string $scope
     * @return OAuthToken
     */
    protected function createNewOAuthToken(string $clientId, string $clientSecret, string $grantType, AccessToken $accessToken, string $scope): OAuthToken
    {
        $oAuthToken = new OAuthToken();
        $oAuthToken->clientId = $clientId;
        $oAuthToken->serviceName = static::getServiceName();
        $oAuthToken->grantType = $grantType;
        $oAuthToken->clientSecret = $clientSecret;
        $oAuthToken->accessToken = $accessToken->getToken();
        $oAuthToken->refreshToken = $accessToken->getRefreshToken();
        $oAuthToken->expires = ($accessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires()) : null);
        $oAuthToken->scope = $scope;

        return $oAuthToken;
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
            'redirectUri' => $this->renderRedirectUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri()
        ], [
            'requestFactory' => $this->getRequestFactory()
        ]);
    }
}
