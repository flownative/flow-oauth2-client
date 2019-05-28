<?php
namespace Flownative\OAuth2\Client\Command;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\ORM\EntityManager as DoctrineEntityManager;

use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\OAuthToken;
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
        $query = new Query(OAuthToken::class);
        $oAuthTokens = $query->execute();

        $rows = [];
        foreach ($oAuthTokens as $oAuthToken) {
            assert($oAuthToken instanceof OAuthToken);
            $rows[] = [
                $oAuthToken->serviceName,
                $oAuthToken->clientId,
                $oAuthToken->grantType,
                $oAuthToken->scope,
                $oAuthToken->expires->format('d. M Y H:i:s')
            ];
        }
        $this->output->outputTable($rows, ['Service Name', 'Client ID', 'Grant Type', 'Scope', 'Expiration Time']);
    }

    /**
     * Remove token
     *
     * This command removes one or all existing OAuth tokens
     *
     * @param string $clientId
     * @param string $serviceName
     * @param bool $all
     * @return void
     * @throws ORMException
     * @throws OptimisticLockException
     * @throws \Doctrine\ORM\TransactionRequiredException
     */
    public function removeCommand(string $clientId = '', string $serviceName = '', bool $all = false): void
    {
        if ((empty($clientId) || empty($serviceName)) && !$all) {
            $this->outputLine('<error>Please specify either --client-id and --service-name or --all.</error>');
            exit(1);
        }

        if ($all) {
            $query = new Query(OAuthToken::class);
            $oAuthTokens = $query->execute();
            foreach ($oAuthTokens as $oAuthToken) {
                assert($oAuthToken instanceof OAuthToken);
                $this->entityManager->remove($oAuthToken);
            }
        } else {
            $oAuthToken = $this->entityManager->find(OAuthToken::class, ['clientId' => $clientId, 'serviceName' => $serviceName]);
            if (!$oAuthToken) {
                $this->outputLine('<error>Specified token was not found.</error>');
                exit(1);
            }
            $this->entityManager->remove($oAuthToken);
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
