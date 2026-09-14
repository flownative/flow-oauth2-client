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

use Neos\Flow\Mvc\Controller\ActionController;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class OAuthControllerTest extends TestCase
{
    /**
     * PHP refuses to load a controller whose properties conflict with those of ActionController, which breaks every request of an application
     */
    #[Test]
    public function controllerCanBeLoadedWithTheInstalledFlowVersion(): void
    {
        self::assertTrue(is_subclass_of(OAuthController::class, ActionController::class));
    }
}
