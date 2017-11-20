<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;

class Version20171120150210 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription()
    {
        return 'Introduce OAuth Token';
    }

    /**
     * @param Schema $schema
     * @return void
     */
    public function up(Schema $schema)
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() != 'mysql', 'Migration can only be executed safely on "mysql".');
        $this->addSql('CREATE TABLE flownative_oauth2_client_oauthtoken (clientid VARCHAR(255) NOT NULL, servicename VARCHAR(255) NOT NULL, clientsecret VARCHAR(255) NOT NULL, accesstoken VARCHAR(255) NOT NULL, refreshtoken VARCHAR(255) NOT NULL, expires DATETIME DEFAULT NULL, PRIMARY KEY(clientid, servicename)) DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci ENGINE = InnoDB');
    }

    /**
     * @param Schema $schema
     * @return void
     */
    public function down(Schema $schema)
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() != 'mysql', 'Migration can only be executed safely on "mysql".');
        $this->addSql('DROP TABLE flownative_oauth2_client_oauthtoken');
    }
}
