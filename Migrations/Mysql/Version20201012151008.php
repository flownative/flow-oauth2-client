<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Exception;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Migrations\AbortMigrationException;

/**
 * Drop the client secret field in Authorization
 */
class Version20201012151008 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription(): string
    {
        return 'Drop the client secret field in Authorization';
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws AbortMigrationException|Exception
     */
    public function up(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization DROP clientsecret');
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws AbortMigrationException|Exception
     */
    public function down(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization ADD clientsecret VARCHAR(5000) CHARACTER SET utf8mb4 DEFAULT NULL COLLATE `utf8mb4_unicode_ci`');
    }
}
