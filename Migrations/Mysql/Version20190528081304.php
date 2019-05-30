<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;

/**
 * Introduce "tokenValues" field
 */
class Version20190528081304 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription()
    {
        return 'Introduce "tokenValues" field';
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws \Doctrine\DBAL\DBALException
     * @throws \Doctrine\DBAL\Migrations\AbortMigrationException
     */
    public function up(Schema $schema)
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() != 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_oauthtoken ADD `tokenvalues` LONGTEXT NOT NULL COMMENT \'(DC2Type:array)\', CHANGE expires expires DATETIME DEFAULT NULL COMMENT \'(DC2Type:datetime_immutable)\'');
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws \Doctrine\DBAL\DBALException
     * @throws \Doctrine\DBAL\Migrations\AbortMigrationException
     */
    public function down(Schema $schema)
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() != 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_oauthtoken DROP `tokenvalues`, CHANGE expires expires DATETIME DEFAULT NULL');
    }
}
