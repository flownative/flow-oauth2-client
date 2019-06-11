<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;

/**
 * Migrate to completely new model
 */
class Version20190610144513 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription()
    {
        return '';
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

        $this->addSql('CREATE TABLE flownative_oauth2_client_authorization (authorizationid VARCHAR(255) NOT NULL, clientid VARCHAR(255) NOT NULL, servicename VARCHAR(255) NOT NULL, granttype VARCHAR(255) NOT NULL, clientsecret VARCHAR(5000) DEFAULT NULL, accesstoken VARCHAR(5000) NOT NULL, refreshtoken VARCHAR(5000) DEFAULT NULL, expires DATETIME DEFAULT NULL COMMENT \'(DC2Type:datetime_immutable)\', scope VARCHAR(255) NOT NULL, tokenvalues LONGTEXT NOT NULL COMMENT \'(DC2Type:array)\', PRIMARY KEY(authorizationid)) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci ENGINE = InnoDB');
        $this->addSql('DROP TABLE flownative_oauth2_client_oauthtoken');
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

        $this->addSql('CREATE TABLE flownative_oauth2_client_oauthtoken (clientid VARCHAR(255) NOT NULL COLLATE utf8_unicode_ci, servicename VARCHAR(255) NOT NULL COLLATE utf8_unicode_ci, clientsecret VARCHAR(5000) DEFAULT NULL COLLATE utf8_unicode_ci, accesstoken VARCHAR(5000) NOT NULL COLLATE utf8_unicode_ci, refreshtoken VARCHAR(5000) DEFAULT NULL COLLATE utf8_unicode_ci, expires DATETIME DEFAULT NULL COMMENT \'(DC2Type:datetime_immutable)\', scope VARCHAR(255) NOT NULL COLLATE utf8_unicode_ci, granttype VARCHAR(255) NOT NULL COLLATE utf8_unicode_ci, tokenvalues LONGTEXT NOT NULL COLLATE utf8_unicode_ci COMMENT \'(DC2Type:array)\', PRIMARY KEY(clientid, servicename)) DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci ENGINE = InnoDB COMMENT = \'\' ');
        $this->addSql('DROP TABLE flownative_oauth2_client_authorization');
    }
}
