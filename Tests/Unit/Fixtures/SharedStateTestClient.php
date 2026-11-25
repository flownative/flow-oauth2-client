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

use Neos\Cache\Frontend\VariableFrontend;

/**
 * A test client which uses the state cache of the test, because the controller creates its client by itself
 */
class SharedStateTestClient extends OAuthTestClient
{
    public static ?VariableFrontend $sharedStateCache = null;

    public function __construct(string $serviceName)
    {
        parent::__construct($serviceName);
        $this->stateCache = self::$sharedStateCache;
    }
}
