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
 * The state of a returning authorization is malformed, unknown, expired or was already used
 *
 * This is usually caused by the browser, for example by reloading the page, and not by a server problem.
 */
class UnknownStateException extends OAuthClientException
{
    protected $statusCode = 400;
}
