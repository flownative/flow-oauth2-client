<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Exception;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Migrations\AbortMigrationException;

/**
 * Adjust column type for serialized access token
 */
class Version20201012142627 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription(): string
    {
        return 'Adjust column type for serialized access token';
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws AbortMigrationException
     * @throws Exception
     */
    public function up(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization CHANGE serializedaccesstoken serializedaccesstoken LONGTEXT DEFAULT NULL');
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws AbortMigrationException
     * @throws Exception
     */
    public function down(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization CHANGE serializedaccesstoken serializedaccesstoken LONGTEXT CHARACTER SET utf8mb4 DEFAULT NULL COLLATE `utf8mb4_unicode_ci` COMMENT \'(DC2Type:json_array)\'');
    }
}
