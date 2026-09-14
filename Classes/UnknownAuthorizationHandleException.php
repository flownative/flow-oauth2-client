<?php
declare(strict_types=1);

namespace Flownative\OAuth2\Client;

/*
 * This file is part of the Flownative.OAuth2.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

/**
 * The handle of a finished authorization is malformed, unknown, expired or already claimed, or another browser presented it
 */
class UnknownAuthorizationHandleException extends OAuthClientException
{
    protected $statusCode = 403;
}
