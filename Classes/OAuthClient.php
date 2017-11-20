<?php

namespace Flownative\OAuth2\Client;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\ORM\EntityManager as DoctrineEntityManager;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
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
     * The OAuth2 client id
     *
     * @var string
     */
    private $clientId;

    /**
     * The service base URI
     * @var string
     */
    private $baseUri;

    /**
     * @var GenericProvider
     */
    private $oAuthProvider;

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
    protected $baseUriSetting;

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
     * Start OAuth authorization
     *
     * @param string $clientId The client id, as provided by the OAuth server
     * @param string $clientSecret The client secret, provided by the OAuth server
     * @param string $returnToUri URI to return to when authorization is finished
     * @return string The URL the browser should redirect to, asking the user to authorize
     */
    public function startAuthorization(string $clientId, string $clientSecret, string $returnToUri)
    {
        $this->oAuthProvider = new GenericProvider([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $this->renderRedirectUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri()
        ]);

        $authorizationUri = $this->oAuthProvider->getAuthorizationUrl();

        $this->logger->log(sprintf(static::getServiceName() . ': Starting authorization for client "%s" using a %s bytes long secret, returning to "%s".', $clientId, strlen($clientSecret), $returnToUri), LOG_INFO);

        $oldOAuthToken = $this->getOAuthToken();
        if ($oldOAuthToken !== null) {
            $this->entityManager->remove($oldOAuthToken);
            $this->entityManager->flush();

            $this->logger->log(sprintf(static::getServiceName() . ': Removed old OAuth token for client "%s".', $oldOAuthToken->clientId), LOG_INFO);
        }

        $this->session->putData(static::getServiceName() . '.oAuthClientId', $clientId);
        $this->session->putData(static::getServiceName() . '.oAuthClientSecret', $clientSecret);
        $this->session->putData(static::getServiceName() . '.oAuthState', $this->oAuthProvider->getState());
        $this->session->putData(static::getServiceName() . '.returnToUri', $returnToUri);
        return $authorizationUri;
    }

    /**
     * Finish an OAuth authorization
     *
     * @param string $code The authorization code given by the OAuth server
     * @param string $state The authorization staten given by the OAuth server
     * @return string The URI to return to
     * @throws IdentityProviderException
     * @throws OAuthClientException
     */
    public function finishAuthorization(string $code, string $state)
    {
        $stateFromSession = $this->session->getData(static::getServiceName() . '.oAuthState');
        if (empty($state) || $stateFromSession !== $state) {
            throw new OAuthClientException('Invalid oAuth2 state.', 1505313625652);
        }

        $clientId = (string)$this->session->getData(static::getServiceName() . '.oAuthClientId');
        $clientSecret = (string)$this->session->getData(static::getServiceName() . '.oAuthClientSecret');

        $this->oAuthProvider = new GenericProvider([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $this->renderRedirectUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri()
        ]);

        try {
            $this->logger->log(sprintf(static::getServiceName() . ': Finishing authorization for client "%s" using a %s bytes long secret.', $clientId, strlen($clientSecret)), LOG_INFO);

            $oldOAuthToken = $this->entityManager->find(OAuthToken::class, ['clientId' => $clientId, 'serviceName' => static::getServiceName()]);
            if ($oldOAuthToken !== null) {
                $this->entityManager->remove($oldOAuthToken);
                $this->entityManager->flush();

                $this->logger->log(sprintf(static::getServiceName() . ': Removed old OAuth token for client "%s".', $clientId), LOG_INFO);
            }

            $accessToken = $this->oAuthProvider->getAccessToken('authorization_code', ['code' => $code]);

            $oAuthToken = new OAuthToken();
            $oAuthToken->clientId = $clientId;
            $oAuthToken->serviceName = static::getServiceName();
            $oAuthToken->clientSecret = $clientSecret;
            $oAuthToken->accessToken = $accessToken->getToken();
            $oAuthToken->refreshToken = $accessToken->getRefreshToken();
            $oAuthToken->expires = ($accessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires()) : null);

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

        $this->oAuthProvider = new GenericProvider([
            'clientId' => $clientId,
            'clientSecret' => $oAuthToken->clientSecret,
            'redirectUri' => $this->renderRedirectUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri()
        ]);

        $this->logger->log(sprintf(static::getServiceName() . ': Refreshing authorization for client "%s" using a %s bytes long secret and refresh token "%s".', $clientId, strlen($oAuthToken->clientSecret), $oAuthToken->refreshToken), LOG_INFO);

        try {
            $accessToken = $this->oAuthProvider->getAccessToken('refresh_token', ['refresh_token' => $oAuthToken->refreshToken]);
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
     * @param string|null $clientId
     * @return OAuthToken|null
     */
    public function getOAuthToken(string $clientId = null): ?OAuthToken
    {
        if ($clientId !== null) {
            $oAuthToken = $this->entityManager->find(OAuthToken::class, ['clientId' => $clientId, 'serviceName' => static::getServiceName()]);
        } else {
            $query = new Query(OAuthToken::class);
            $oAuthToken = $query->execute()->getFirst();
        }
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

        if ($oAuthToken->expires < new \DateTimeImmutable()) {
            $this->refreshAuthorization($oAuthToken->clientId, '');
            $oAuthToken = $this->getOAuthToken();
        }

        $this->oAuthProvider = new GenericProvider([
            'clientId' => $oAuthToken->clientId,
            'clientSecret' => $oAuthToken->clientSecret,
            'redirectUri' => $this->renderRedirectUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri()
        ]);

        $body = ($bodyFields !== [] ? \GuzzleHttp\json_encode($bodyFields) : '');

        return $this->oAuthProvider->getAuthenticatedRequest(
            $method,
            $this->getBaseUri() . $relativeUri,
            $oAuthToken->accessToken,
            [
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
    protected function renderRedirectUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getHttpRequest();
        } else {
            putenv('FLOW_REWRITEURLS=1');
            $httpRequest = Request::createFromEnvironment();
            $httpRequest->setBaseUri(new Uri($this->baseUriSetting));
        }
        $actionRequest = new ActionRequest($httpRequest);

        $this->uriBuilder->reset();
        $this->uriBuilder->setRequest($actionRequest);
        $this->uriBuilder->setCreateAbsoluteUri(true);

        return $this->uriBuilder->uriFor('finishAuthorization', ['serviceName' => static::getServiceName()], 'OAuth', 'Flownative.OAuth2.Client');
    }
}
