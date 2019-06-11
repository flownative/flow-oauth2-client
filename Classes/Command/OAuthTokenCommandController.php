<?php
namespace Flownative\OAuth2\Client\Command;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\ORM\EntityManager as DoctrineEntityManager;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\Authorization;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Persistence\Doctrine\Query;

final class OAuthTokenCommandController extends CommandController
{
    /**
     * @var DoctrineEntityManager
     */
    protected $entityManager;

    /**
     * @param DoctrineObjectManager $entityManager
     * @return void
     */
    public function injectEntityManager(DoctrineObjectManager $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * List tokens
     *
     * This command lists all known OAuth tokens
     *
     * @return void
     */
    public function listCommand(): void
    {
        $query = new Query(Authorization::class);
        $oAuthTokens = $query->execute();

        $rows = [];
        foreach ($oAuthTokens as $oAuthToken) {
            assert($oAuthToken instanceof Authorization);
            $rows[] = [
                $oAuthToken->authorizationId,
                $oAuthToken->serviceName,
                $oAuthToken->clientId,
                $oAuthToken->grantType,
                $oAuthToken->scope,
                $oAuthToken->expires->format('d. M Y H:i:s'),
                implode(', ', array_keys($oAuthToken->tokenValues))
            ];
        }
        $this->output->outputTable($rows, ['Authorization Id', 'Service Name', 'Client ID', 'Grant Type', 'Scope', 'Expiration Time', 'Values']);
    }

    /**
     * Remove token
     *
     * This command removes one or all existing OAuth tokens
     *
     * @param string $authorizationId
     * @param bool $all
     * @return void
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws \Doctrine\ORM\TransactionRequiredException
     */
    public function removeCommand(string $authorizationId = '', bool $all = false): void
    {
        if (empty($authorizationId) && !$all) {
            $this->outputLine('<error>Please specify either --authorization-id or --all.</error>');
            exit(1);
        }

        if ($all) {
            $query = new Query(Authorization::class);
            $authorizations = $query->execute();
            foreach ($authorizations as $authorization) {
                assert($authorization instanceof Authorization);
                $this->entityManager->remove($authorization);
            }
        } else {
            $authorization = $this->entityManager->find(Authorization::class, ['authorizationId' => $authorizationId]);
            if (!$authorization) {
                $this->outputLine('<error>Specified authorization was not found.</error>');
                exit(1);
            }
            $this->entityManager->remove($authorization);
        }
        try {
            $this->entityManager->flush();
        } catch (OptimisticLockException $e) {
        } catch (ORMException $e) {
            $this->outputLine('<error>Failed:</error> ' . $e->getMessage());
            exit(1);
        }
        $this->outputLine('<success>Done</success>');
    }
}
