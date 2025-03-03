<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

use Doctrine\ORM\EntityManagerInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Tool\RequestFactory;
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
use Neos\Flow\Persistence\Doctrine\Query;
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
    public const AUTHORIZATION_ID_QUERY_PARAMETER_NAME_PREFIX = 'flownative_oauth2_authorization_id';

    protected string $serviceName;

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
     * @Flow\InjectConfiguration(path="token.defaultLifetime", package="Flownative.OAuth2.Client")
     * @var int|null
     */
    protected $defaultTokenLifetime;

    protected EntityManagerInterface $entityManager;

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
     * Requests an access token.
     *
     * This method is used using the OAuth Client Credentials Flow for machine-to-machine applications.
     * Therefore the grant type must be Authorization::GRANT_CLIENT_CREDENTIALS. You need to specify the
     * client identifier and client secret and may optionally specify a scope.
     *
     * - The scope which may consist of multiple identifiers, separated by comma.
     * - Additional parameters to provide in the request body while requesting the token, like ['audience' => 'https://www.example.com/api/v1']
     *
     * @throws IdentityProviderException
     * @throws GuzzleException
     */
    public function requestAccessToken(string $serviceName, string $clientId, string $clientSecret, string $scope,  array $additionalParameters = []): void
    {
        $authorizationId = Authorization::generateAuthorizationIdForClientCredentialsGrant($serviceName, $clientId, $clientSecret, $scope, $additionalParameters);
        $this->logger->info(sprintf('OAuth (%s): Retrieving access token using client credentials grant for client "%s" using a %s bytes long secret. (authorization id: %s)', static::getServiceType(), $clientId, strlen($clientSecret), $authorizationId));

        $existingAuthorization = $this->getAuthorization($authorizationId);
        if ($existingAuthorization !== null) {
            $this->entityManager->remove($existingAuthorization);
            $this->entityManager->flush();

            $this->logger->info(sprintf('OAuth (%s): Removed old OAuth token for client "%s". (authorization id: %s)', static::getServiceType(), $clientId, $authorizationId), LogEnvironment::fromMethodName(__METHOD__));
        }

        $accessToken = $this->createOAuthProvider($clientId, $clientSecret)->getAccessToken(Authorization::GRANT_CLIENT_CREDENTIALS, $additionalParameters);
        $authorization = new Authorization($authorizationId, $serviceName, $clientId, Authorization::GRANT_CLIENT_CREDENTIALS, $scope);
        $authorization->setAccessToken($accessToken);

        $this->logger->info(sprintf('OAuth (%s): Persisted new OAuth authorization %s for client "%s" with expiry time %s. (authorization id: %s)', static::getServiceType(), $authorizationId, $clientId, $accessToken->getExpires(), $authorizationId), LogEnvironment::fromMethodName(__METHOD__));

        $this->entityManager->persist($authorization);
        $this->entityManager->flush();
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
     * This returns the URL the browser should redirect to, asking the user to authorize.
     *
     * The scope to request for authorization must be scope ids separated by space, e.g. "openid profile email"
     *
     * @throws OAuthClientException
     * @throws \DateMalformedStringException
     */
    public function startAuthorization(string $clientId, string $clientSecret, UriInterface $returnToUri, string $scope): UriInterface
    {
        $authorizationId = $this->generateAuthorizationIdForAuthorizationCodeGrant($clientId);
        return $this->startAuthorizationWithId($authorizationId, $clientId, $clientSecret, $returnToUri, $scope);
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
     * @throws OAuthClientException
     * @throws \DateMalformedStringException
     */
    public function startAuthorizationWithId(string $authorizationId, string $clientId, string $clientSecret, UriInterface $returnToUri, string $scope): UriInterface
    {
        $authorization = new Authorization($authorizationId, static::getServiceType(), $clientId, Authorization::GRANT_AUTHORIZATION_CODE, $scope);
        if ($this->defaultTokenLifetime !== null) {
            $authorization->setExpires(new \DateTimeImmutable('+ ' . $this->defaultTokenLifetime . ' seconds'));
        }

        $this->logger->info(sprintf('OAuth (%s): Starting authorization %s using client id "%s", a %s bytes long secret and scope "%s".', static::getServiceType(), $authorization->getAuthorizationId(), $clientId, strlen($clientSecret), $scope));

        try {
            $oldAuthorization = $this->entityManager->find(Authorization::class, $authorization->getAuthorizationId());
            if ($oldAuthorization !== null) {
                $authorization = $oldAuthorization;
            }
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (\Exception $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed storing authorization in database: %s', static::getServiceType(), $exception->getMessage()), 1568727133);
        }

        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);
        $authorizationUri = new Uri($oAuthProvider->getAuthorizationUrl(['scope' => $scope]));

        if ($clientId === $clientSecret) {
            $this->logger->error(sprintf('OAuth (%s): Client ID and Client secret are the same! Please check your configuration.', static::getServiceType()));
        }

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
            throw new OAuthClientException(sprintf('OAuth (%s): Failed setting cache entry for authorization: %s', static::getServiceType(), $exception->getMessage()), 1560178858);
        }

        return $authorizationUri;
    }

    /**
     * Finish an OAuth authorization with the Authorization Code flow
     *
     * @throws OAuthClientException
     * @throws GuzzleException
     */
    public function finishAuthorization(string $stateIdentifier, string $code, string $scope): UriInterface
    {
        $stateFromCache = $this->stateCache->get($stateIdentifier);
        if (empty($stateFromCache)) {
            throw new OAuthClientException(sprintf('OAuth: Finishing authorization failed because oAuth state %s could not be retrieved from the state cache.', $stateIdentifier), 1558956494);
        }
        $this->stateCache->remove($stateIdentifier);

        $authorizationId = $stateFromCache['authorizationId'];
        $clientId = $stateFromCache['clientId'];
        $clientSecret = $stateFromCache['clientSecret'];
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);

        $this->logger->info(sprintf('OAuth (%s): Finishing authorization for client "%s", authorization id "%s", using state %s.', static::getServiceType(), $clientId, $authorizationId, $stateIdentifier));
        try {
            $authorization = $this->entityManager->find(Authorization::class, $authorizationId);
            if (!$authorization instanceof Authorization) {
                throw new OAuthClientException(sprintf('OAuth2 (%s): Finishing authorization failed because authorization %s could not be retrieved from the database.', static::getServiceType(), $authorizationId), 1568710771);
            }

            if ($authorization->getGrantType() !== Authorization::GRANT_AUTHORIZATION_CODE) {
                throw new OAuthClientException(sprintf('OAuth2 (%s): Finishing authorization failed because authorization %s does not have the authorization code flow type!', static::getServiceType(), $authorizationId), 1597312780);
            }

            $this->logger->debug(sprintf('OAuth (%s): Retrieving an OAuth access token for authorization "%s" in exchange for the code %s', static::getServiceType(), $authorizationId, str_repeat('*', strlen($code) - 3) . substr($code, -3, 3)));
            $accessToken = $oAuthProvider->getAccessToken(Authorization::GRANT_AUTHORIZATION_CODE, ['code' => $code]);
            $this->logger->info(sprintf('OAuth (%s): Persisting OAuth token for authorization "%s" with expiry time %s.', static::getServiceType(), $authorizationId, $accessToken->getExpires()));

            $authorization->setAccessToken($accessToken);

            $accessTokenValues = $accessToken->getValues();
            $scope = $accessTokenValues['scope'] ?? $scope;
            $authorization->setScope($scope);

            $this->entityManager->persist($authorization);
            $this->entityManager->flush();

        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187001671, $exception);
        }

        $returnToUri = new Uri($stateFromCache['returnToUri']);
        $returnToUri = $returnToUri->withQuery(trim($returnToUri->getQuery() . '&' . self::generateAuthorizationIdQueryParameterName(static::getServiceType()) . '=' . $authorizationId, '&'));

        $this->logger->debug(sprintf('OAuth (%s): Finished authorization "%s", $returnToUri is %s.', static::getServiceType(), $authorizationId, $returnToUri));
        return $returnToUri;
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
            $this->logger->debug(sprintf('OAuth (%s): Removed authorization id %s', static::getServiceType(), $authorizationId), LogEnvironment::fromMethodName(__METHOD__));
        }
    }

    public function renderFinishAuthorizationUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getHttpRequest();
        } else {
            putenv('FLOW_REWRITEURLS=1');
            $httpRequest = $this->serverRequestFactory->createServerRequest('GET', new Uri($this->flowBaseUriSetting));
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
     */
    public function shutdownObject(): void
    {
        $garbageCollectionProbability = (string)$this->garbageCollectionProbability;
        $decimals = strlen(strrchr($garbageCollectionProbability, '.') ?: '') - 1;
        $factor = ($decimals > -1) ? $decimals * 10 : 1;
        try {
            if (random_int(1, 100 * $factor) <= ($this->garbageCollectionProbability * $factor)) {
                $this->removeExpiredAuthorizations();
                $this->stateCache->collectGarbage();
            }
        } catch (\Exception) {
        }
    }
}
