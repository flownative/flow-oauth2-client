<?php
namespace Flownative\OAuth2\Client\Command;

use Doctrine\Common\Persistence\ObjectManager as DoctrineObjectManager;
use Doctrine\ORM\EntityManager as DoctrineEntityManager;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\Authorization;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Persistence\Doctrine\Query;

final class OAuthCommandController extends CommandController
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
     * List authorizations
     *
     * This command lists all known OAuth authorizations. With authorizations we keep track
     * of access tokens for a given OAuth connection. An authorization is identified by
     * a hash over service name, client id, grant type and scope.
     *
     * @return void
     */
    public function listAuthorizationsCommand(): void
    {
        $query = new Query(Authorization::class);
        $authorizations = $query->execute();

        $rows = [];
        foreach ($authorizations as $authorization) {
            assert($authorization instanceof Authorization);
            $accessToken = $authorization->getAccessToken();
            $expires = $accessToken ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires())->format('d.m.Y H:i:s') : '';
            $values = $accessToken ? implode(', ', array_keys($accessToken->getValues())) : '';

            $rows[] = [
                $authorization->getAuthorizationId(),
                $authorization->getServiceName(),
                $authorization->getClientId(),
                $authorization->getGrantType(),
                $authorization->getScope(),
                $expires,
                $values
            ];
        }
        $this->output->outputTable($rows, ['Authorization Id', 'Service Name', 'Client ID', 'Grant Type', 'Scope', 'Expiration Time', 'Values']);
    }

    /**
     * Remove authorization
     *
     * This command removes one or all existing authorizations
     *
     * @param string $id
     * @param bool $all
     * @return void
     * @throws
     */
    public function removeAuthorizationsCommand(string $id = '', bool $all = false): void
    {
        if (empty($id) && !$all) {
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
            $authorization = $this->entityManager->find(Authorization::class, ['authorizationId' => $id]);
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
