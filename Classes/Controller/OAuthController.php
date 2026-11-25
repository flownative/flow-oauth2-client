<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client\Controller;

use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use Flownative\OAuth2\Client\UnknownStateException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Reflection\ReflectionService;
use Psr\Log\LogLevel;

final class OAuthController extends ActionController
{
    private const int MALFORMED_STATE_EXCEPTION_CODE = 1789386787;
    private const int MAXIMUM_LOG_LINE_LENGTH = 500;
    private const int MAXIMUM_LOGGED_SERVICE_NAME_LENGTH = 100;
    private const int MAXIMUM_HOST_LENGTH = 255;

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
     * same applies to a state which was started in another browser. The reason for such a refusal is logged as a
     * notice, for a malformed state only for debugging.
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
        } catch (UnknownStateException $exception) {
            // A malformed state mostly comes from bots probing the endpoint, not from a person signing in
            $logLevel = $exception->getCode() === self::MALFORMED_STATE_EXCEPTION_CODE ? LogLevel::DEBUG : LogLevel::NOTICE;
            $this->logger?->log($logLevel, self::composeLogLine($exception->getMessage(), $serviceName, sprintf(' The return for service "%s" at host "%s" was refused. (%d)', self::describeServiceName($serviceName), $this->describeHost(), $exception->getCode())), LogEnvironment::fromMethodName(__METHOD__));
            $this->throwStatus(400, null, 'The authorization is unknown, has expired or was started in another browser. Please start again.');
        } catch (OAuthClientException $exception) {
            // Flow's exception handling would store the URL of this request, which contains the code and the state
            $this->logger?->error(self::composeLogLine($exception->getMessage(), $serviceName, sprintf(' Finishing the authorization for service "%s" failed. (%d)', self::describeServiceName($serviceName), $exception->getCode())), LogEnvironment::fromMethodName(__METHOD__));
            $this->throwStatus(502, null, 'The authorization server could not complete the authorization. Please start again later.');
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

    /**
     * The host and the port of this request, without the path and the query, which contain the state and the code
     *
     * The browser chooses the host through the Host or X-Forwarded-Host header, so anything unusual is left out.
     */
    private function describeHost(): string
    {
        $uri = $this->request->getHttpRequest()->getUri();
        $host = strtolower($uri->getHost()) . ($uri->getPort() !== null ? ':' . $uri->getPort() : '');
        return preg_match('/^[a-z0-9.\-\[\]:]{1,' . self::MAXIMUM_HOST_LENGTH . '}\z/', $host) === 1 ? $host : '(invalid)';
    }

    /**
     * The service name comes from the route, so quotes or padding in it could forge the host and the code of a line
     */
    private static function describeServiceName(string $serviceName): string
    {
        return substr(preg_replace('/[^A-Za-z0-9._:-]/', '?', $serviceName), 0, self::MAXIMUM_LOGGED_SERVICE_NAME_LENGTH);
    }

    /**
     * One line of printable characters, so that values from the request can't forge other lines
     *
     * The reason is shortened first, so that the context with the host and the code always stays complete at the end.
     */
    private static function composeLogLine(string $reason, string $serviceName, string $context): string
    {
        $reason = preg_replace('/[^\x20-\x7E]/', '?', str_replace($serviceName, self::describeServiceName($serviceName), $reason));
        $context = preg_replace('/[^\x20-\x7E]/', '?', $context);
        return substr($reason, 0, max(0, self::MAXIMUM_LOG_LINE_LENGTH - strlen($context))) . $context;
    }
}
