<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client\Tests\Unit\Fixtures;

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Flownative\OAuth2\Client\OAuthClient;

final class OAuthTestClient extends OAuthClient
{
    public const TEST_SERVICE_TYPE = 'TestServiceType';
    public const TEST_BASE_URI = 'https://localbeach.net/';
    public const TEST_CLIENT_ID = 'my-client-id';

    public function getServiceType(): string
    {
        return self::TEST_SERVICE_TYPE;
    }

    public function getBaseUri(): string
    {
        return self::TEST_BASE_URI;
    }

    public function getClientId(): string
    {
        return self::TEST_CLIENT_ID;
    }
}
