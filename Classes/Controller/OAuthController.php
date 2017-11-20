<?php
namespace Flownative\OAuth2\Client\Controller;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use Neos\Flow\Annotations\CompileStatic;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Reflection\ReflectionService;

final class OAuthController extends ActionController
{

    /**
     * @var array
     */
    private $services;

    public function initializeObject()
    {
        $this->services = self::detectServices($this->objectManager);
    }

    /**
     * Start OAuth2 authorization
     *
     * @param string $consumerKey
     * @param string $consumerSecret
     * @param string $returnToUri
     * @param string $serviceName
     * @throws OAuthClientException
     */
    public function startAuthorizationAction(string $consumerKey, string $consumerSecret, string $returnToUri, string $serviceName)
    {
        if (!isset($this->services[$serviceName])) {
            throw new OAuthClientException('Unknown client service.', 1511187873921);
        }

        /** @var $client OAuthClient **/
        $client = new $this->services[$serviceName];
        $authorizeUri = $client->startAuthorization($consumerKey, $consumerSecret, $returnToUri);
        $this->redirectToUri($authorizeUri);
    }

    /**
     * Finish OAuth2 authorization
     *
     * @param string $code
     * @param string $state
     * @param string $serviceName
     * @throws OAuthClientException
     */
    public function finishAuthorizationAction(string $code, string $state, string $serviceName)
    {
        if (!isset($this->services[$serviceName])) {
            throw new OAuthClientException('Unknown client service.', 1511193117184);
        }

        /** @var $client OAuthClient **/
        $client = new $this->services[$serviceName];
        $returnToUri = $client->finishAuthorization($code, $state);
        $this->redirectToUri($returnToUri);
    }

    /**
     * Refresh OAuth2 authorization
     *
     * @param string $consumerKey
     * @param string $returnToUri
     * @param string $serviceName
     * @throws OAuthClientException
     */
    public function refreshAuthorizationAction(string $consumerKey, string $returnToUri, string $serviceName)
    {
        if (!isset($this->services[$serviceName])) {
            throw new OAuthClientException('Unknown client service.', 1511193121713);
        }

        /** @var $client OAuthClient **/
        $client = new $this->services[$serviceName];
        $authorizeUri = $client->refreshAuthorization($consumerKey, $returnToUri);
        $this->redirectToUri($authorizeUri);
    }

    /**
     * Detects and collects all existing OAuth2 Client Services
     *
     * @param ObjectManagerInterface $objectManager
     * @return array
     * @CompileStatic
     */
    protected static function detectServices(ObjectManagerInterface $objectManager): array
    {
        $services = [];
        /** @var ReflectionService $reflectionService */
        $reflectionService = $objectManager->get(ReflectionService::class);
        foreach ($reflectionService->getAllSubClassNamesForClass(OAuthClient::class) as $serviceClassName) {
            if ($reflectionService->isClassAbstract($serviceClassName)) {
                continue;
            }
            $services[call_user_func_array([$serviceClassName, 'getServiceName'], [])] = $serviceClassName;
        }
        return $services;
    }
}
