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

use Doctrine\ORM\EntityManagerInterface;
use Neos\Cache\Backend\TransientMemoryBackend;
use Neos\Cache\Frontend\VariableFrontend;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use ReflectionProperty;
use RuntimeException;

class GarbageCollectorTest extends TestCase
{
    public static function probabilities(): array
    {
        return [
            'never for 0 %' => [0, 1, false],
            'always for 100 %' => [100, 1_000_000, true],
            'last hit for 1 %' => [1, 10_000, true],
            'first miss for 1 %' => [1, 10_001, false],
            'last hit for 0.42 %' => [0.42, 4_200, true],
            'first miss for 0.42 %' => [0.42, 4_201, false],
            'last hit for 0.001 %' => [0.001, 10, true],
            'first miss for 0.001 %' => [0.001, 11, false],
        ];
    }

    #[Test]
    #[DataProvider('probabilities')]
    public function isDueHitsTheConfiguredShareOfRandomNumbers(float|int $probability, int $randomNumber, bool $expectedResult): void
    {
        self::assertSame($expectedResult, GarbageCollector::isDue($probability, $randomNumber));
    }

    #[Test]
    public function collectWithProbabilityDoesNothingForProbabilityZero(): void
    {
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects($this->never())->method('createQuery');

        (new GarbageCollector($entityManager, $this->createStateCache(), 0))->collectWithProbability();
    }

    #[Test]
    public function collectWithProbabilityLogsFailedGarbageCollection(): void
    {
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('createQuery')->willThrowException(new RuntimeException('The database is not available'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error')->with($this->stringContains('The database is not available'));
        $garbageCollector = new GarbageCollector($entityManager, $this->createStateCache(), 100);
        (new ReflectionProperty($garbageCollector, 'logger'))->setValue($garbageCollector, $logger);

        $garbageCollector->collectWithProbability();
    }

    #[Test]
    public function collectWithProbabilityCollectsGarbageAtMostOncePerRequest(): void
    {
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects($this->once())->method('createQuery')->willThrowException(new RuntimeException('The database is not available'));
        $garbageCollector = new GarbageCollector($entityManager, $this->createStateCache(), 100);

        $garbageCollector->collectWithProbability();
        $garbageCollector->collectWithProbability();
    }

    private function createStateCache(): VariableFrontend
    {
        $stateCache = new VariableFrontend('state', new TransientMemoryBackend());
        $stateCache->initializeObject();
        return $stateCache;
    }
}
