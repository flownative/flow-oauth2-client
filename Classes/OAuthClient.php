<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

use Doctrine\ORM\EntityManagerInterface;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Tool\RequestFactory;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Neos\Cache\Exception;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Http\Exception as HttpException;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\Exception\MissingActionNameException;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Http\Factories\ServerRequestFactory;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;

/**
 * Base class for an OAuth client
 */
abstract class OAuthClient
{
    /**
     * Name of the HTTP query parameter used for passing around the authorization id
     */
    public const string AUTHORIZATION_ID_QUERY_PARAMETER_NAME_PREFIX = 'flownative_oauth2_authorization_id';

    /**
     * Name of the HTTP query parameter which passes the error code of a refused authorization to the application
     */
    public const string AUTHORIZATION_ERROR_QUERY_PARAMETER_NAME_PREFIX = 'flownative_oauth2_error';

    private const array RESERVED_AUTHORIZATION_PARAMETER_NAMES = ['client_id', 'client_secret', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'state', 'code_challenge', 'code_challenge_method', 'request', 'request_uri'];

    private const array RESERVED_TOKEN_REQUEST_PARAMETER_NAMES = ['grant_type', 'client_id', 'client_secret', 'redirect_uri', 'scope', 'code', 'code_verifier', 'refresh_token'];

    /**
     * Error codes of RFC 6749, section 4.1.2.1, and OpenID Connect Core, section 3.1.2.6
     */
    private const array DEFINED_AUTHORIZATION_ERRORS = ['invalid_request', 'unauthorized_client', 'access_denied', 'unsupported_response_type', 'invalid_scope', 'server_error', 'temporarily_unavailable', 'interaction_required', 'login_required', 'account_selection_required', 'consent_required', 'invalid_request_uri', 'invalid_request_object', 'request_not_supported', 'request_uri_not_supported', 'registration_not_supported'];

    private const int STATE_LIFETIME = 3600; # seconds

    private const int AUTHORIZATION_HANDLE_LIFETIME = 60; # seconds between the return from the OAuth server and claiming the authorization

    protected string $serviceName;

    protected EntityManagerInterface $entityManager;

    #[Flow\Inject]
    protected UriBuilder $uriBuilder;

    #[Flow\Inject]
    protected Bootstrap $bootstrap;

    #[Flow\Inject]
    protected ServerRequestFactory $serverRequestFactory;

    #[Flow\Inject]
    protected GarbageCollector $garbageCollector;

    /**
     * Not typed, because the OAuth client of flownative/openidconnect-client redeclares this property without a type
     *
     * @var string|null
     */
    #[Flow\InjectConfiguration(path: 'http.baseUri', package: 'Neos.Flow')]
    protected $flowBaseUriSetting;

    #[Flow\InjectConfiguration(path: 'token.defaultLifetime', package: 'Flownative.OAuth2.Client')]
    protected ?int $defaultTokenLifetime = null; # seconds; null if new tokens don't expire

    #[Flow\Inject]
    protected ?LoggerInterface $logger = null;

    /**
     * Not typed, because Flow injects the cache configured in Objects.yaml lazily and the dependency proxy would not match the type
     *
     * @var VariableFrontend
     */
    #[Flow\Inject]
    protected $stateCache;

    public function __construct(string $serviceName)
    {
        $this->serviceName = $serviceName;
    }

    public function injectEntityManager(EntityManagerInterface $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Returns the service type, i.e. a specific implementation of this client to use,
     * for example, "Github", "oidc", ...
     */
    abstract public static function getServiceType(): string;

    /**
     * Returns the service name, i.e. something like an instance name of the concrete implementation of this client,
     * for example, "SpecificGithubConnection", "MySpecialService", ...
     */
    public function getServiceName(): string
    {
        return $this->serviceName;
    }

    /**
     * Returns the OAuth server's base URI, for example https://myservice.flownative.com
     */
    abstract public function getBaseUri(): string;

    /**
     * Returns the current client id (for sending authenticated requests)
     * which is known by the OAuth server
     */
    abstract public function getClientId(): string;

    /**
     * Returns the secret of the given client id, which is sent to the token endpoint when an authorization finishes
     */
    abstract public function getClientSecret(string $clientId): string;

    /**
     * Returns the OAuth service endpoint for the access token.
     * Override this method if needed.
     */
    public function getAccessTokenUri(): string
    {
        return trim($this->getBaseUri(), '/') . '/oauth/token';
    }

    /**
     * Returns the OAuth service endpoint for authorizing a token.
     * Override this method if needed.
     */
    public function getAuthorizeTokenUri(): string
    {
        return trim($this->getBaseUri(), '/') . '/oauth/token/authorize';
    }

    /**
     * Returns the OAuth service endpoint for accessing the resource owner details.
     * Override this method if needed.
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
     */
    public function getRequestFactory(): RequestFactory
    {
        return new RequestFactory();
    }

    /**
     * Generates the URL query parameter name which is used for passing the authorization id of a
     * finishing authorization to Flow (via the "Return URL").
     *
     * The $serviceType  is the "class" of the of the service, for example, "Github", "oidc", ...
     */
    public static function generateAuthorizationIdQueryParameterName(string $serviceType): string
    {
        return self::AUTHORIZATION_ID_QUERY_PARAMETER_NAME_PREFIX . '_' . $serviceType;
    }

    /**
     * Generates the URL query parameter name which passes the error code of a refused authorization to Flow
     * (via the "Return URL").
     */
    public static function generateAuthorizationErrorQueryParameterName(string $serviceType): string
    {
        return self::AUTHORIZATION_ERROR_QUERY_PARAMETER_NAME_PREFIX . '_' . $serviceType;
    }

    /**
     * Requests an access token.
     *
     * This method is used using the OAuth Client Credentials Flow for machine-to-machine applications. The token is stored as an
     * authorization, whose id Authorization::generateAuthorizationIdForClientCredentialsGrant() returns for the same arguments.
     * An existing token is replaced only after the new token was issued.
     *
     * - The scope may consist of multiple identifiers, separated by space. An empty scope is not sent, so that the server uses its default.
     * - Additional parameters to provide in the request body while requesting the token, like ['audience' => 'https://www.example.com/api/v1']
     *
     * @throws IdentityProviderException
     * @throws GuzzleException
     */
    public function requestAccessToken(string $serviceName, string $clientId, string $clientSecret, string $scope, array $additionalParameters = []): void
    {
        $reservedParameterNames = array_intersect(array_keys($additionalParameters), self::RESERVED_TOKEN_REQUEST_PARAMETER_NAMES);
        if ($reservedParameterNames !== []) {
            throw new \InvalidArgumentException(sprintf('OAuth (%s): The additional parameters must not contain "%s", because the client sets them itself.', static::getServiceType(), implode('", "', $reservedParameterNames)), 1789391047);
        }

        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant($serviceName, $clientId, $scope, $additionalParameters);
        $this->logger?->info(sprintf('OAuth (%s): Retrieving access token using client credentials grant for client "%s". (authorization id: %s)', static::getServiceType(), $clientId, $authorizationId), LogEnvironment::fromMethodName(__METHOD__));

        $tokenRequestParameters = $scope !== '' ? [...$additionalParameters, 'scope' => $scope] : $additionalParameters;
        $accessToken = $this->createOAuthProvider($clientId, $clientSecret)->getAccessToken(Authorization::GRANT_CLIENT_CREDENTIALS, $tokenRequestParameters);

        $authorization = $this->getAuthorization($authorizationId) ?? new Authorization($authorizationId, $serviceName, $clientId, Authorization::GRANT_CLIENT_CREDENTIALS, $scope);
        $this->storeAccessToken($authorization, $accessToken);

        $this->logger?->info(sprintf('OAuth (%s): Persisted new OAuth authorization %s for client "%s" with expiry time %s.', static::getServiceType(), $authorizationId, $clientId, $accessToken->getExpires()), LogEnvironment::fromMethodName(__METHOD__));
    }

    /**
     * Returns an authorization id taking the service type and service name into account.
     *
     * @throws OAuthClientException
     */
    public function generateAuthorizationIdForAuthorizationCodeGrant(string $clientId): string
    {
        return Authorization::generateAuthorizationIdForAuthorizationCodeGrant(static::getServiceType(), $this->getServiceName(), $clientId);
    }

    /**
     * Start OAuth authorization with the Authorization Code flow
     *
     * This returns the URL the browser should redirect to, asking the user to authorize. The response which redirects the browser
     * must also set the cookie of the given browser binding, otherwise the authorization can't be finished.
     *
     * The scope to request for authorization must be scope ids separated by space, e.g. "openid profile email"
     *
     * @param array $authorizationParameters Additional query parameters for the authorization endpoint, for example ['prompt' => 'login']
     * @param string|null $metadata Stored with the authorization when it is finished, see Authorization::getMetadata()
     * @throws OAuthClientException
     */
    public function startAuthorization(string $clientId, UriInterface $returnToUri, string $scope, BrowserBinding $browserBinding, array $authorizationParameters = [], ?string $metadata = null): UriInterface
    {
        $authorizationId = $this->generateAuthorizationIdForAuthorizationCodeGrant($clientId);
        return $this->startAuthorizationWithId($authorizationId, $clientId, $returnToUri, $scope, $browserBinding, $authorizationParameters, $metadata);
    }

    /**
     * Start OAuth authorization with the Authorization Code flow
     * based on a specified authorization identifier.
     *
     * This returns the URL the browser should redirect to, asking the user to authorize.
     *
     * Note that, if you use this method, it is your responsibility to provide a
     * meaningful authorization id. You might weaken the security of your
     * application if you use an id which is deterministic or can be guessed by
     * an attacker.
     *
     * If in doubt, always use startAuthorization() instead.
     *
     * The scope to request for authorization must be scope ids separated by space, e.g. "openid profile email"
     *
     * The authorization is stored only when it is finished. Until then, its data is kept in the state cache.
     *
     * @param array $authorizationParameters Additional query parameters for the authorization endpoint, for example ['prompt' => 'login']
     * @param string|null $metadata Stored with the authorization when it is finished, see Authorization::getMetadata()
     * @throws OAuthClientException
     */
    public function startAuthorizationWithId(string $authorizationId, string $clientId, UriInterface $returnToUri, string $scope, BrowserBinding $browserBinding, array $authorizationParameters = [], ?string $metadata = null): UriInterface
    {
        $reservedParameterNames = array_intersect(array_keys($authorizationParameters), self::RESERVED_AUTHORIZATION_PARAMETER_NAMES);
        if ($reservedParameterNames !== []) {
            throw new \InvalidArgumentException(sprintf('OAuth (%s): The authorization parameters must not contain "%s", because the client sets them itself.', static::getServiceType(), implode('", "', $reservedParameterNames)), 1789131855);
        }

        $this->logger?->info(sprintf('OAuth (%s): Starting authorization for service "%s" using client id "%s" and scope "%s".', static::getServiceType(), $this->getServiceName(), $clientId, $scope), LogEnvironment::fromMethodName(__METHOD__));

        // The token request must repeat the redirect URI exactly (RFC 6749, section 4.1.3), even if the browser returns through another host name
        $redirectUri = $this->renderFinishAuthorizationUri();
        $clientSecret = $this->getClientSecret($clientId);
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret, $redirectUri);
        $authorizationUri = new Uri($oAuthProvider->getAuthorizationUrl(array_merge($authorizationParameters, ['scope' => $scope])));

        if ($clientId === $clientSecret) {
            $this->logger?->error(sprintf('OAuth (%s): Client ID and Client secret are the same! Please check your configuration.', static::getServiceType()));
        }

        try {
            // The state contains no client secret, because cache entries end up in backups and in shared cache backends
            $this->stateCache->set(
                $oAuthProvider->getState(),
                [
                    'serviceType' => static::getServiceType(),
                    'serviceName' => $this->getServiceName(),
                    'tokenEndpoint' => $this->getAccessTokenUri(),
                    'browserBindingCookieName' => $browserBinding->cookieName,
                    'browserBindingSecretHash' => $browserBinding->getSecretHash(),
                    'pkceCode' => $oAuthProvider->getPkceCode(),
                    'authorizationId' => $authorizationId,
                    'clientId' => $clientId,
                    'returnToUri' => (string)$returnToUri,
                    'redirectUri' => $redirectUri,
                    'scope' => $scope,
                    'metadata' => $metadata,
                ],
                [],
                self::STATE_LIFETIME
            );
        } catch (Exception $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed setting cache entry for authorization: %s', static::getServiceType(), $exception->getMessage()), 1560178858);
        }

        return $authorizationUri;
    }

    /**
     * Finish an OAuth authorization with the Authorization Code flow
     *
     * Returns the return URI of the authorization, with a handle of the authorization as an additional query parameter. The application
     * gets the authorization with claimAuthorization(), in the same browser and within a minute.
     *
     * @param array $cookies The cookies of the current request, which must contain the cookie of the browser binding
     * @throws UnknownStateException
     * @throws OAuthClientException
     */
    public function finishAuthorization(string $stateIdentifier, string $code, array $cookies): UriInterface
    {
        $stateFromCache = $this->takeState($stateIdentifier, $cookies);

        $authorizationId = $stateFromCache['authorizationId'];
        $clientId = $stateFromCache['clientId'];
        $oAuthProvider = $this->createOAuthProvider($clientId, $this->getClientSecret($clientId), $stateFromCache['redirectUri']);
        if (is_string($stateFromCache['pkceCode'] ?? null)) {
            $oAuthProvider->setPkceCode($stateFromCache['pkceCode']);
        }

        $this->logger?->info(sprintf('OAuth (%s): Finishing authorization for service "%s" using client id "%s".', static::getServiceType(), $this->getServiceName(), $clientId), LogEnvironment::fromMethodName(__METHOD__));
        try {
            // An authorization with the same id exists if startAuthorizationWithId() was called with the id of a finished authorization
            $authorization = $this->entityManager->find(Authorization::class, $authorizationId);
            if ($authorization === null) {
                $authorization = new Authorization($authorizationId, static::getServiceType(), $clientId, Authorization::GRANT_AUTHORIZATION_CODE, $stateFromCache['scope']);
            } elseif ($authorization->getGrantType() !== Authorization::GRANT_AUTHORIZATION_CODE) {
                throw new OAuthClientException(sprintf('OAuth2 (%s): Finishing authorization failed because an existing authorization with the same id does not have the authorization code flow type.', static::getServiceType()), 1597312780);
            } else {
                $authorization->setScope($stateFromCache['scope']);
            }
            if (is_string($stateFromCache['metadata'] ?? null)) {
                $authorization->setMetadata($stateFromCache['metadata']);
            }

            try {
                $accessToken = $oAuthProvider->getAccessToken(Authorization::GRANT_AUTHORIZATION_CODE, ['code' => $code]);
            } catch (GuzzleException|\UnexpectedValueException|\InvalidArgumentException $exception) {
                throw new OAuthClientException(sprintf('OAuth (%s): The token request of service "%s" failed: %s', static::getServiceType(), $this->getServiceName(), $exception->getMessage()), 1789386786, $exception);
            }
            $this->storeAccessToken($authorization, $accessToken);
        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187001671, $exception);
        }

        // The authorization id is the key of the stored tokens, so it must not appear in URLs, which end up in logs and browser histories
        $authorizationHandle = bin2hex(random_bytes(32));
        try {
            $this->stateCache->set(
                self::getAuthorizationHandleCacheIdentifier($authorizationHandle),
                [
                    'serviceType' => static::getServiceType(),
                    'serviceName' => $this->getServiceName(),
                    'browserBindingCookieName' => $stateFromCache['browserBindingCookieName'],
                    'browserBindingSecretHash' => $stateFromCache['browserBindingSecretHash'],
                    'authorizationId' => $authorizationId,
                ],
                [],
                self::AUTHORIZATION_HANDLE_LIFETIME
            );
        } catch (Exception $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed setting cache entry for authorization handle: %s', static::getServiceType(), $exception->getMessage()), 1789395652);
        }

        $returnToUri = new Uri($stateFromCache['returnToUri']);
        return $returnToUri->withQuery(trim($returnToUri->getQuery() . '&' . self::generateAuthorizationIdQueryParameterName(static::getServiceType()) . '=' . $authorizationHandle, '&'));
    }

    /**
     * Returns the authorization of a handle from the return URI of finishAuthorization(), which can't be used again afterwards
     *
     * The handle is only accepted within a minute, by the client of the same service, and together with the cookie of the browser
     * binding which started the authorization. Afterwards, the application should remove that cookie, see BrowserBinding::createRemovalCookie().
     *
     * @param array $cookies The cookies of the current request
     * @throws UnknownAuthorizationHandleException
     */
    public function claimAuthorization(string $authorizationHandle, array $cookies): Authorization
    {
        if (preg_match('/^[0-9a-f]{64}$/', $authorizationHandle) !== 1) {
            throw new UnknownAuthorizationHandleException(sprintf('OAuth (%s): The authorization handle is malformed.', static::getServiceType()), 1789395646);
        }
        $cacheIdentifier = self::getAuthorizationHandleCacheIdentifier($authorizationHandle);
        $handleEntry = $this->stateCache->get($cacheIdentifier);
        if (!is_array($handleEntry)) {
            throw new UnknownAuthorizationHandleException(sprintf('OAuth (%s): The authorization handle is unknown, expired or was already claimed.', static::getServiceType()), 1789395647);
        }

        // The handle is not removed, so that a request from another browser can't take it away from the browser which started the authorization
        if (($handleEntry['serviceType'] ?? null) !== static::getServiceType() || ($handleEntry['serviceName'] ?? null) !== $this->getServiceName()) {
            throw new UnknownAuthorizationHandleException(sprintf('OAuth (%s): The authorization handle belongs to another service than "%s".', static::getServiceType(), $this->getServiceName()), 1789395648);
        }
        if (!BrowserBinding::isPresentInCookies($handleEntry['browserBindingCookieName'] ?? '', $handleEntry['browserBindingSecretHash'] ?? '', $cookies)) {
            throw new UnknownAuthorizationHandleException(sprintf('OAuth (%s): The authorization was not started in this browser.', static::getServiceType()), 1789395649);
        }
        $this->stateCache->remove($cacheIdentifier);

        $authorization = $this->getAuthorization($handleEntry['authorizationId']);
        if ($authorization === null) {
            throw new UnknownAuthorizationHandleException(sprintf('OAuth (%s): The authorization of the handle no longer exists.', static::getServiceType()), 1789395650);
        }
        return $authorization;
    }

    /**
     * Ends an authorization which the OAuth server refused, for example because the user denied access
     *
     * Returns the return URI of the authorization, with the error code as an additional query parameter. Applications
     * may display the error code, so codes which RFC 6749 and OpenID Connect don't define are replaced by "server_error".
     *
     * @param array $cookies The cookies of the current request, which must contain the cookie of the browser binding
     * @throws UnknownStateException
     */
    public function finishAuthorizationWithError(string $stateIdentifier, string $error, array $cookies): UriInterface
    {
        $stateFromCache = $this->takeState($stateIdentifier, $cookies);
        $definedError = in_array($error, self::DEFINED_AUTHORIZATION_ERRORS, true) ? $error : 'server_error';
        $this->logger?->notice(sprintf('OAuth (%s): The OAuth server refused the authorization with the error "%s".', static::getServiceType(), $definedError), LogEnvironment::fromMethodName(__METHOD__));

        $returnToUri = new Uri($stateFromCache['returnToUri']);
        return $returnToUri->withQuery(trim($returnToUri->getQuery() . '&' . self::generateAuthorizationErrorQueryParameterName(static::getServiceType()) . '=' . $definedError, '&'));
    }

    /**
     * Returns the specified Authorization record, if it exists
     */
    public function getAuthorization(string $authorizationId): ?Authorization
    {
        $oAuthToken = $this->entityManager->getRepository(Authorization::class)->find(['authorizationId' => $authorizationId]);
        return ($oAuthToken instanceof Authorization) ? $oAuthToken : null;
    }

    /**
     * Removes the specified Authorization record
     */
    public function removeAuthorization(string $authorizationId): void
    {
        $existingAuthorization = $this->getAuthorization($authorizationId);
        if ($existingAuthorization !== null) {
            $this->entityManager->remove($existingAuthorization);
            $this->entityManager->flush();
            $this->logger?->debug(sprintf('OAuth (%s): Removed an authorization of service "%s"', static::getServiceType(), $this->getServiceName()), LogEnvironment::fromMethodName(__METHOD__));
        }
    }

    /**
     * Returns the URI to which the OAuth server redirects the browser when the authorization is finished
     *
     * @throws OAuthClientException
     */
    public function renderFinishAuthorizationUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getHttpRequest();
        } elseif (is_string($this->flowBaseUriSetting) && $this->flowBaseUriSetting !== '') {
            $httpRequest = $this->serverRequestFactory->createServerRequest('GET', new Uri($this->flowBaseUriSetting));
        } else {
            throw new OAuthClientException(sprintf('OAuth (%s): Outside of a web request, for example in a command or a job, the redirect URI can only be rendered if the setting "Neos.Flow.http.baseUri" is configured.', static::getServiceType()), 1789386788);
        }
        $actionRequest = ActionRequest::fromHttpRequest($httpRequest);

        $this->uriBuilder->reset();
        $this->uriBuilder->setRequest($actionRequest);
        $this->uriBuilder->setCreateAbsoluteUri(true);

        try {
            return $this->uriBuilder
                ->reset()
                ->setCreateAbsoluteUri(true)
                ->uriFor('finishAuthorization', ['serviceType' => static::getServiceType(), 'serviceName' => $this->getServiceName()], 'OAuth', 'Flownative.OAuth2.Client');
        } catch (MissingActionNameException|HttpException) {
            return '';
        }
    }

    /**
     * Helper method to set metadata on an Authorization instance. Changes are
     * persisted immediately.
     */
    public function setAuthorizationMetadata(string $authorizationId, string $metadata): void
    {
        $authorization = $this->getAuthorization($authorizationId);
        if ($authorization === null) {
            throw new \RuntimeException(sprintf('Failed setting authorization metadata: authorization %s was not found', $authorizationId), 1631821719);
        }
        $authorization->setMetadata($metadata);

        $this->entityManager->persist($authorization);
        $this->entityManager->flush();
    }

    /**
     * @param string|null $redirectUri null for grants without a redirect, like client credentials
     */
    protected function createOAuthProvider(string $clientId, string $clientSecret, ?string $redirectUri = null): GenericProvider
    {
        return new GenericProvider([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri,
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri(),
            'pkceMethod' => $this->getPkceMethod(),
        ], [
            'requestFactory' => $this->getRequestFactory(),
            'httpClient' => $this->createHttpClient(),
        ]);
    }

    /**
     * Returns the PKCE method (RFC 7636) for the authorization code flow
     *
     * Override this method and return null only for OAuth servers which reject the PKCE parameters.
     */
    protected function getPkceMethod(): ?string
    {
        return AbstractProvider::PKCE_METHOD_S256;
    }

    /**
     * Returns the HTTP client for requests to the OAuth server
     *
     * Override this method to configure timeouts or a proxy, or to replace the client in tests.
     */
    protected function createHttpClient(): ClientInterface
    {
        return new HttpClient();
    }

    /**
     * Shuts down this client
     *
     * This method must not be called manually – it is invoked by Flow's object
     * management.
     */
    public function shutdownObject(): void
    {
        $this->garbageCollector->collectWithProbability();
    }

    /**
     * Stores the token with the given authorization, together with its expiration time and the scope which the server granted
     */
    private function storeAccessToken(Authorization $authorization, AccessTokenInterface $accessToken): void
    {
        $authorization->setAccessToken($accessToken);
        if ($accessToken->getExpires() === null) {
            $authorization->setExpires($this->defaultTokenLifetime !== null ? new \DateTimeImmutable('@' . (time() + $this->defaultTokenLifetime)) : null);
        }

        // The token response only contains the scope if the server granted a different one (RFC 6749, section 5.1)
        $grantedScope = $accessToken->getValues()['scope'] ?? null;
        if (is_string($grantedScope)) {
            $authorization->setScope($grantedScope);
        }

        $this->entityManager->persist($authorization);
        $this->entityManager->flush();
    }

    /**
     * Returns the data which was stored for the given state and removes it, so that each state is accepted only once
     *
     * Only the client of the service which started the authorization accepts the state, and only from the browser which started it.
     * The state refers to the credentials of that service, which must never be sent to the token endpoint of another service.
     *
     * @throws UnknownStateException
     */
    private function takeState(string $stateIdentifier, array $cookies): array
    {
        // The cache rejects other identifiers with an exception
        if (preg_match('/^[a-zA-Z0-9_-]{1,250}$/', $stateIdentifier) !== 1) {
            throw new UnknownStateException(sprintf('OAuth (%s): The state of the returning authorization is malformed.', static::getServiceType()), 1789386787);
        }
        $stateFromCache = $this->stateCache->get($stateIdentifier);
        if (!is_array($stateFromCache)) {
            throw new UnknownStateException(sprintf('OAuth (%s): The state of the returning authorization is unknown, expired or was already used.', static::getServiceType()), 1558956494);
        }

        // The state is not removed, so that a request to the wrong callback URL can't cancel an authorization in progress
        if (($stateFromCache['serviceType'] ?? null) !== static::getServiceType() || ($stateFromCache['serviceName'] ?? null) !== $this->getServiceName()) {
            throw new UnknownStateException(sprintf('OAuth (%s): The state of the returning authorization belongs to another service than "%s".', static::getServiceType(), $this->getServiceName()), 1789391698);
        }
        if (($stateFromCache['tokenEndpoint'] ?? null) !== $this->getAccessTokenUri()) {
            throw new UnknownStateException(sprintf('OAuth (%s): The token endpoint of service "%s" has changed since the authorization was started.', static::getServiceType(), $this->getServiceName()), 1789391699);
        }
        // An attacker could otherwise make the browser of a victim finish an authorization which the attacker started
        if (!BrowserBinding::isPresentInCookies($stateFromCache['browserBindingCookieName'] ?? '', $stateFromCache['browserBindingSecretHash'] ?? '', $cookies)) {
            throw new UnknownStateException(sprintf('OAuth (%s): The returning authorization was not started in this browser.', static::getServiceType()), 1789395645);
        }

        $this->stateCache->remove($stateIdentifier);
        return $stateFromCache;
    }

    /**
     * Only the hash of the handle is stored, so that the cache backend doesn't contain usable handles
     */
    private static function getAuthorizationHandleCacheIdentifier(string $authorizationHandle): string
    {
        return 'authorization_handle_' . hash('sha256', $authorizationHandle);
    }
}
