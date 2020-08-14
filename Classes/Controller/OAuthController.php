<?php
namespace Flownative\OAuth2\Client\Controller;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Annotations\CompileStatic;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Reflection\ReflectionService;

final class OAuthController extends ActionController
{
    /**
     * @var array
     */
    private $serviceTypes;

    /**
     * @return void
     */
    public function initializeObject(): void
    {
        $this->serviceTypes = self::detectServiceTypes($this->objectManager);
    }

    /**
     * Start OAuth2 authorization
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param Uri $returnToUri
     * @param string $serviceType
     * @param string $serviceName
     * @param string $scope
     * @throws OAuthClientException
     * @throws StopActionException
     * @throws UnsupportedRequestTypeException
     */
    public function startAuthorizationAction(string $clientId, string $clientSecret, Uri $returnToUri, string $serviceType, string $serviceName, string $scope): void
    {
        if (!isset($this->serviceTypes[$serviceType])) {
            throw new OAuthClientException(sprintf('Failed starting OAuth2 authorization, because the given service type "%s" is unknown.', $serviceType), 1511187873921);
        }

        $client = new $this->serviceTypes[$serviceName]($serviceName);
        assert($client instanceof OAuthClient);
        $authorizeUri = $client->startAuthorization($clientId, $clientSecret, $returnToUri, $scope);
        $this->redirectToUri($authorizeUri);
    }

    /**
     * Finish OAuth2 authorization
     *
     * This action passes the given state and code to the OAuth client in order to finish an authorization in progress.
     * If the authorization could be finished successfully, the action will redirect to the return URI which was specified
     * while starting the authorization.
     *
     * @param string $serviceType The OAuth service type, ie. the type identifying the package / class implementing OAuth
     * @param string $serviceName The OAuth service name, ie. the identifier of the concrete configuration of the given OAuth service implementation
     * @param string $state The state by which the OAuth client can find the authorization in progress
     * @param string $code The code issued by the OAuth server
     * @param string $scope The scope issued by the OAuth server
     * @throws OAuthClientException
     * @throws StopActionException
     * @throws UnsupportedRequestTypeException
     */
    public function finishAuthorizationAction(string $serviceType, string $serviceName, string $state, string $code, string $scope = ''): void
    {
        if (!isset($this->serviceTypes[$serviceType])) {
            throw new OAuthClientException(sprintf('OAuth: Failed finishing OAuth2 authorization because the given service type "%s" is unknown.', $serviceName), 1511193117184);
        }
        $client = new $this->serviceTypes[$serviceType]($serviceName);
        if (!$client instanceof OAuthClient) {
            throw new OAuthClientException(sprintf('OAuth: Failed finishing authorization because of unexpected class type: "%s" must implement %s.', get_class($client), OAuthClient::class), 1568735389);
        }
        $this->redirectToUri($client->finishAuthorization($state, $code, $scope));
    }

    /**
     * Detects and collects all existing OAuth2 Client Services
     *
     * @param ObjectManagerInterface $objectManager
     * @return array
     * @CompileStatic
     */
    protected static function detectServiceTypes(ObjectManagerInterface $objectManager): array
    {
        $serviceTypes = [];
        /** @var ReflectionService $reflectionService */
        $reflectionService = $objectManager->get(ReflectionService::class);
        foreach ($reflectionService->getAllSubClassNamesForClass(OAuthClient::class) as $serviceTypeClassName) {
            if ($reflectionService->isClassAbstract($serviceTypeClassName)) {
                continue;
            }
            $serviceType = call_user_func_array([$serviceTypeClassName, 'getServiceType'], []);
            $serviceTypes[$serviceType] = $serviceTypeClassName;
        }
        return $serviceTypes;
    }
}
