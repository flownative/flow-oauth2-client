<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client\Controller;

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Flownative\OAuth2\Client\BrowserBinding;
use Flownative\OAuth2\Client\Tests\Unit\Fixtures\OAuthTestClient;
use Flownative\OAuth2\Client\Tests\Unit\Fixtures\SharedStateTestClient;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\ActionResponse;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\Exception\StopActionException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Http\Message\UriInterface;
use Psr\Log\LogLevel;
use ReflectionProperty;
use Stringable;

class OAuthControllerTest extends TestCase
{
    private const string SERVICE_NAME = 'my-service-name';
    private const string HOST = 'acme.cell-1.example.com:8443';
    private const string CODE = 'the-secret-code';

    private BrowserBinding $browserBinding;

    private array $logRecords = []; # the records the controller logged, as [level, message]

    protected function setUp(): void
    {
        $stateCache = new VariableFrontend('state', new TransientMemoryBackend());
        $stateCache->initializeObject();
        SharedStateTestClient::$sharedStateCache = $stateCache;
        $this->browserBinding = BrowserBinding::generate();
    }

    protected function tearDown(): void
    {
        SharedStateTestClient::$sharedStateCache = null;
    }

    /**
     * PHP refuses to load a controller whose properties conflict with those of ActionController, which breaks every request of an application
     */
    #[Test]
    public function controllerCanBeLoadedWithTheInstalledFlowVersion(): void
    {
        self::assertTrue(is_subclass_of(OAuthController::class, ActionController::class));
    }

    public static function refusedReturns(): array
    {
        return [
            'malformed state' => [1789386787, LogLevel::DEBUG],
            'unknown state' => [1558956494, LogLevel::NOTICE],
            'state of another service' => [1789391698, LogLevel::NOTICE],
            'changed token endpoint' => [1789391699, LogLevel::NOTICE],
            'started in another browser' => [1789395645, LogLevel::NOTICE],
        ];
    }

    #[Test]
    #[DataProvider('refusedReturns')]
    public function refusedReturnIsLoggedWithReasonAndHostButWithoutStateAndCode(int $exceptionCode, string $logLevel): void
    {
        $clientClassName = SharedStateTestClient::class;
        $cookies = $this->browserCookies();
        $state = match ($exceptionCode) {
            1789386787 => 'not a state!',
            1558956494 => str_repeat('a', 32),
            1789391698 => $this->startAuthorization('other-service-name'),
            default => $this->startAuthorization(self::SERVICE_NAME),
        };
        if ($exceptionCode === 1789391699) {
            $clientClassName = (new class(self::SERVICE_NAME) extends SharedStateTestClient {
                public function getAccessTokenUri(): string
                {
                    return 'https://other-server.example.com/oauth/token';
                }
            })::class;
        }
        if ($exceptionCode === 1789395645) {
            $cookies = [];
        }

        $this->finishAuthorization($clientClassName, self::SERVICE_NAME, $state, $cookies, 'https://' . self::HOST);

        self::assertCount(1, $this->logRecords);
        [$actualLogLevel, $message] = $this->logRecords[0];
        self::assertSame($logLevel, $actualLogLevel);
        self::assertStringStartsWith('OAuth (' . OAuthTestClient::TEST_SERVICE_TYPE . '): ', $message);
        self::assertStringEndsWith(sprintf(' The return for service "%s" at host "%s" was refused. (%d)', self::SERVICE_NAME, self::HOST, $exceptionCode), $message);
        self::assertStringNotContainsString($state, $message);
        self::assertStringNotContainsString(self::CODE, $message);
    }

    #[Test]
    public function refusedReturnIsLoggedAsOneCompleteLine(): void
    {
        $state = $this->startAuthorization(self::SERVICE_NAME);

        $this->finishAuthorization(SharedStateTestClient::class, self::SERVICE_NAME, $state, [], 'https://acme.example.com');

        self::assertSame([[LogLevel::NOTICE, 'OAuth (TestServiceType): The returning authorization was not started in this browser. The return for service "my-service-name" at host "acme.example.com" was refused. (1789395645)']], $this->logRecords);
    }

    #[Test]
    public function refusedReturnLogsNoValueOfTheCookieOfAnotherBrowser(): void
    {
        $state = $this->startAuthorization(self::SERVICE_NAME);
        $cookie = BrowserBinding::generate()->createCookie();

        $this->finishAuthorization(SharedStateTestClient::class, self::SERVICE_NAME, $state, [$cookie->getName() => $cookie->getValue()], 'https://' . self::HOST);

        self::assertCount(1, $this->logRecords);
        self::assertStringContainsString('(1789395645)', $this->logRecords[0][1]);
        self::assertStringNotContainsString($cookie->getValue(), $this->logRecords[0][1]);
    }

    public static function hostileRequests(): array
    {
        $forgedLine = "\"\r\n2026-11-25 12:00:00 OAuth: Signed in as admin \e[31m";
        return [
            'service name with a forged line' => ['other' . $forgedLine, self::HOST, self::HOST],
            'host with a quote and a forged line' => [self::SERVICE_NAME, 'acme.example.com' . $forgedLine, '(invalid)'],
            'very long host' => [self::SERVICE_NAME, str_repeat('a', 300) . '.example.com', '(invalid)'],
            'very long service name' => [str_repeat('x', 1000), self::HOST, self::HOST],
        ];
    }

    #[Test]
    public function serviceNameCannotForgeTheHostOrTheCodeOfTheLogLine(): void
    {
        $state = $this->startAuthorization(self::SERVICE_NAME);
        $serviceName = 'x" at host "good.example" was refused. (1558956494)' . str_repeat(' ', 600);

        $this->finishAuthorization(SharedStateTestClient::class, $serviceName, $state, [], 'https://' . self::HOST);

        self::assertCount(1, $this->logRecords);
        $message = $this->logRecords[0][1];
        self::assertLessThanOrEqual(500, strlen($message));
        self::assertStringEndsWith(sprintf(' at host "%s" was refused. (1789391698)', self::HOST), $message);
        self::assertStringNotContainsString('"good.example"', $message);
        self::assertSame(1, substr_count($message, ' at host "'));
    }

    #[Test]
    #[DataProvider('hostileRequests')]
    public function refusedReturnIsLoggedAsOneLineOfPrintableCharactersEvenForHostileRequests(string $serviceName, string $host, string $loggedHost): void
    {
        // The state of another service carries the service name into the message of the exception as well
        $state = $this->startAuthorization(self::SERVICE_NAME);
        // Guzzle refuses such hosts, while the Host header of a request may contain them
        $requestUri = $this->createStub(UriInterface::class);
        $requestUri->method('getHost')->willReturn($host);
        $requestUri->method('getPort')->willReturn(null);

        $this->finishAuthorization(SharedStateTestClient::class, $serviceName, $state, [], 'https://localhost', $requestUri);

        self::assertCount(1, $this->logRecords);
        $message = $this->logRecords[0][1];
        self::assertMatchesRegularExpression('/^[\x20-\x7E]{1,500}\z/', $message);
        self::assertStringNotContainsString($state, $message);
        if (strlen($serviceName) < 100) {
            self::assertStringContainsString(sprintf(' at host "%s" was refused. (', $loggedHost), $message);
        }
    }

    private function startAuthorization(string $serviceName): string
    {
        $authorizationUri = (new SharedStateTestClient($serviceName))->startAuthorization(OAuthTestClient::TEST_CLIENT_ID, new Uri('https://www.example.com/return'), 'openid', $this->browserBinding);
        parse_str($authorizationUri->getQuery(), $queryParameters);
        return $queryParameters['state'];
    }

    /**
     * Calls the controller like the browser which returns from the OAuth server, and expects it to refuse the return
     */
    private function finishAuthorization(string $clientClassName, string $serviceName, string $state, array $cookies, string $baseUri, ?UriInterface $requestUri = null): void
    {
        $logger = new class($this->logRecords) extends AbstractLogger {
            public function __construct(private array &$records)
            {
            }

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->records[] = [$level, (string)$message];
            }
        };
        $httpRequest = (new ServerRequest('GET', $baseUri . '/oauth/finish?' . http_build_query(['state' => $state, 'code' => self::CODE])))->withCookieParams($cookies);
        if ($requestUri !== null) {
            $httpRequest = $httpRequest->withUri($requestUri, true);
        }
        $controller = new OAuthController();
        (new ReflectionProperty($controller, 'serviceTypes'))->setValue($controller, [OAuthTestClient::TEST_SERVICE_TYPE => $clientClassName]);
        (new ReflectionProperty($controller, 'logger'))->setValue($controller, $logger);
        (new ReflectionProperty($controller, 'request'))->setValue($controller, ActionRequest::fromHttpRequest($httpRequest));
        (new ReflectionProperty($controller, 'response'))->setValue($controller, new ActionResponse());

        try {
            $controller->finishAuthorizationAction(OAuthTestClient::TEST_SERVICE_TYPE, $serviceName, $state, self::CODE);
            self::fail('The return was accepted');
        } catch (StopActionException $exception) {
            self::assertSame(400, $exception->response->getStatusCode());
        }
    }

    private function browserCookies(): array
    {
        $cookie = $this->browserBinding->createCookie();
        return [$cookie->getName() => $cookie->getValue()];
    }
}
