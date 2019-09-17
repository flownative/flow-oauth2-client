<?php
namespace Flownative\OAuth2\Client\Controller;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use Neos\Flow\Annotations\CompileStatic;
use Neos\Flow\Http\Uri;
use Neos\Flow\Mvc\Controller\ActionController;
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
     * @throws OAuthClientException
     * @throws \Doctrine\ORM\ORMException
     * @throws \Doctrine\ORM\OptimisticLockException
     * @throws \Doctrine\ORM\TransactionRequiredException
     * @throws \Neos\Flow\Mvc\Exception\StopActionException
     * @throws \Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException
     */
    public function startAuthorizationAction(string $clientId, string $clientSecret, Uri $returnToUri, string $serviceType, string $serviceName): void
    {
//        if (!isset($this->serviceTypes[$serviceType])) {
//            throw new OAuthClientException(sprintf('Failed starting OAuth2 authorization, because the given service type "%s" is unknown.', $serviceType), 1511187873921);
//        }
//
//        $client = new $this->serviceTypes[$serviceName]($serviceName);
//        assert($client instanceof OAuthClient);
//        $authorizeUri = $client->startAuthorization($clientId, $clientSecret, $returnToUri);
//        $this->redirectToUri($authorizeUri);
    }

    /**
     * Finish OAuth2 authorization
     *
     * @param string $code
     * @param string $state
     * @param string $serviceType
     * @param string $serviceName
     * @param string $scope
     * @throws
     */
    public function finishAuthorizationAction(string $code, string $state, string $serviceType, string $serviceName, string $scope = ''): void
    {
        if (!isset($this->serviceTypes[$serviceType])) {
            throw new OAuthClientException(sprintf('OAuth: Failed finishing OAuth2 authorization because the given service type "%s" is unknown.', $serviceName), 1511193117184);
        }

        $client = new $this->serviceTypes[$serviceType]($serviceName);
        assert($client instanceof OAuthClient);

        $returnToUri = $client->finishAuthorization($code, $state, $scope);
        $this->redirectToUri($returnToUri);
    }

    /**
     * Refresh OAuth2 authorization
     *
     * @param string $clientId
     * @param string $returnToUri
     * @param string $serviceName
     * @throws
     */
    public function refreshAuthorizationAction(string $clientId, string $returnToUri, string $serviceName): void
    {
//        if (!isset($this->serviceTypes[$serviceName])) {
//            throw new OAuthClientException('Unknown client service.', 1511193121713);
//        }
//
//        /** @var $client OAuthClient * */
//        $client = new $this->serviceTypes[$serviceName];
//        $authorizeUri = $client->refreshAuthorization($clientId, $returnToUri);
//        $this->redirectToUri($authorizeUri);
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
