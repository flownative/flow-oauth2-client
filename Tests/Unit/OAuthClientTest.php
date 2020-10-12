<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

require_once('Fixtures/OAuthTestClient.php');

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ObjectRepository;
use Flownative\OAuth2\Client\Tests\Unit\Fixtures\OAuthTestClient;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Flow\Persistence\Repository;
use Neos\Flow\Tests\UnitTestCase;

class OAuthClientTest extends UnitTestCase
{
    /**
     * @test
     */
    public function constructorSetsServiceName(): void
    {
        $client = new OAuthTestClient('my-service-name');
        self::assertSame('my-service-name', $client->getServiceName());
    }

    /**
     * @test
     */
    public function baseUriIsUsedForConstructingEndpointUris(): void
    {
        $client = new OAuthTestClient('my-service-name');

        $actualUri = $client->getAccessTokenUri();
        $expectedUri = OAuthTestClient::TEST_BASE_URI . 'oauth/token';
        self::assertSame($expectedUri, $actualUri);

        $actualUri = $client->getAuthorizeTokenUri();
        $expectedUri = OAuthTestClient::TEST_BASE_URI . 'oauth/token/authorize';
        self::assertSame($expectedUri, $actualUri);

        $actualUri = $client->getResourceOwnerUri();
        $expectedUri = OAuthTestClient::TEST_BASE_URI . 'oauth/token/resource';
        self::assertSame($expectedUri, $actualUri);
    }

    /**
     * @test
     */
    public function generateAuthorizationIdQueryParameterName(): void
    {
       self::assertSame('flownative_oauth2_authorization_id_test-service-type', OAuthTestClient::generateAuthorizationIdQueryParameterName('test-service-type'));
    }

    /**
     * @test
     */
    public function getAuthorizationFetchesAuthorizationFromRepository(): void
    {
        $authorizationId = '3d47f0eafd6a8b49e32b55103d817b6e4ef489e7';
        $expectedAuthorization = new Authorization($authorizationId, 'service', 'clientId',Authorization::GRANT_AUTHORIZATION_CODE, 'profile');

        $mockRepository = $this->createMock(ObjectRepository::class);
        $mockRepository->method('find')->with(['authorizationId' => $authorizationId])->willReturn($expectedAuthorization);

        $mockEntityManager = $this->createMock(EntityManagerInterface::class);
        $mockEntityManager->method('getRepository')->with(Authorization::class)->willReturn($mockRepository);

        $client = new OAuthTestClient('my-service-name');
        $client->injectEntityManager($mockEntityManager);

        $actualAuthorization = $client->getAuthorization($authorizationId);
        self::assertSame($expectedAuthorization, $actualAuthorization);
    }
}
