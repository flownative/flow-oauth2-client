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

use Exception;

/**
 * A host which a StateSigner may not sign for; the host usually comes from a request header, so this is no programming error
 */
final class TargetHostNotAllowedException extends Exception
{
}
