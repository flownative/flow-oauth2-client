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

use DateTimeImmutable;
use DateTimeZone;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use Neos\Cache\Frontend\FrontendInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Psr\Log\LoggerInterface;

/**
 * Removes expired authorizations and expired entries of the state cache
 *
 * OAuth clients trigger a garbage collection with the configured probability when
 * they shut down. Applications which set the probability to 0 should run
 * ./flow oauth:collectgarbage regularly instead.
 */
#[Flow\Scope('singleton')]
class GarbageCollector
{
    private const int RANDOM_NUMBER_RANGE = 1_000_000;

    private bool $collectionWasConsidered = false;

    #[Flow\Inject]
    protected ?LoggerInterface $logger = null;

    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly FrontendInterface $stateCache,
        private readonly float|int $probability, # percent
    ) {
    }

    /**
     * Returns the number of removed authorizations
     *
     * @throws Exception
     */
    public function collect(): int
    {
        $this->stateCache->collectGarbage();

        // A bulk delete does not load the expired authorizations into memory and leaves other pending changes alone.
        return (int)$this->entityManager
            ->createQuery(sprintf('DELETE FROM %s authorization WHERE authorization.expires < :now', Authorization::class))
            ->setParameter('now', new DateTimeImmutable('now', new DateTimeZone('UTC')), Types::DATETIME_IMMUTABLE)
            ->execute();
    }

    /**
     * Collects garbage with the configured probability, at most once per request
     *
     * Failures are logged instead of thrown, because this runs while Flow shuts down.
     */
    public function collectWithProbability(): void
    {
        if ($this->collectionWasConsidered) {
            return;
        }
        $this->collectionWasConsidered = true;

        if (!self::isDue($this->probability, random_int(1, self::RANDOM_NUMBER_RANGE))) {
            return;
        }
        try {
            $this->collect();
        } catch (Exception $exception) {
            $this->logger?->error(sprintf('OAuth: Garbage collection failed: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
        }
    }

    /**
     * Tells if a garbage collection is due for the given random number between 1 and 1,000,000
     */
    public static function isDue(float|int $probability, int $randomNumber): bool
    {
        return $randomNumber <= (int)round($probability * self::RANDOM_NUMBER_RANGE / 100);
    }
}
