<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client\Controller;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OAuth2\Client\UnknownStateException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Reflection\ReflectionService;

final class OAuthController extends ActionController
{
    private array $serviceTypes;

    /**
     * @return void
     */
    public function initializeObject(): void
    {
        $this->serviceTypes = self::detectServiceTypes($this->objectManager);
    }

    /**
     * Finish OAuth2 authorization
     *
     * The OAuth server redirects the browser to this action, either with a code or with an error. In both cases, the
     * action redirects to the return URI which was specified while starting the authorization. A malformed, unknown
     * or already used state results in status 400, because it usually comes from a reloaded or bookmarked page. The
     * same applies to a state which was started in another browser.
     *
     * @param string $serviceType The OAuth service type, ie. the type identifying the package / class implementing OAuth
     * @param string $serviceName The OAuth service name, ie. the identifier of the concrete configuration of the given OAuth service implementation
     * @param string $state The state by which the OAuth client can find the authorization in progress
     * @param string $code The code issued by the OAuth server if the authorization succeeded
     * @param string $error The error code sent by the OAuth server if the authorization was refused
     * @throws OAuthClientException
     * @throws StopActionException
     * @throws UnsupportedRequestTypeException
     */
    public function finishAuthorizationAction(string $serviceType, string $serviceName, string $state = '', string $code = '', string $error = ''): void
    {
        if (!isset($this->serviceTypes[$serviceType])) {
            throw new OAuthClientException(sprintf('OAuth: Failed finishing OAuth2 authorization because the given service type "%s" is unknown.', $serviceType), 1511193117184);
        }
        $client = new $this->serviceTypes[$serviceType]($serviceName);
        if (!$client instanceof OAuthClient) {
            throw new OAuthClientException(sprintf('OAuth: Failed finishing authorization because of unexpected class type: "%s" must implement %s.', get_class($client), OAuthClient::class), 1568735389);
        }
        if ($code === '' && $error === '') {
            $this->throwStatus(400, null, 'The OAuth server sent neither a code nor an error.');
        }

        $cookies = $this->request->getHttpRequest()->getCookieParams();
        try {
            $returnToUri = $error !== '' ? $client->finishAuthorizationWithError($state, $error, $cookies) : $client->finishAuthorization($state, $code, $cookies);
        } catch (UnknownStateException) {
            $this->throwStatus(400, null, 'The authorization is unknown, has expired or was started in another browser. Please start again.');
        }
        $this->redirectToUri($returnToUri);
    }

    /**
     * Detects and collects all existing OAuth2 Client Services
     *
     * @param ObjectManagerInterface $objectManager
     * @return array
     */
    #[Flow\CompileStatic]
    protected static function detectServiceTypes(ObjectManagerInterface $objectManager): array
    {
        $serviceTypes = [];
        /** @var ReflectionService $reflectionService */
        $reflectionService = $objectManager->get(ReflectionService::class);
        foreach ($reflectionService->getAllSubClassNamesForClass(OAuthClient::class) as $serviceTypeClassName) {
            if ($reflectionService->isClassAbstract($serviceTypeClassName)) {
                continue;
            }
            $serviceType = $serviceTypeClassName::getServiceType();
            $serviceTypes[$serviceType] = $serviceTypeClassName;
        }
        return $serviceTypes;
    }
}
