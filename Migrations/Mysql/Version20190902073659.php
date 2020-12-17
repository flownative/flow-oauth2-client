<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;

/**
 * Authorizations v2
 */
class Version20190902073659 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription()
    {
        return 'Authorizations v2';
    }

    /**
     * @param Schema $schema
     * @return void
     */
    public function up(Schema $schema)
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() != 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization ADD serializedaccesstoken LONGTEXT DEFAULT NULL COMMENT \'(DC2Type:json_array)\', DROP accesstoken, DROP refreshtoken, DROP expires, DROP tokenvalues');
    }

    /**
     * @param Schema $schema
     * @return void
     */
    public function down(Schema $schema)
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() != 'mysql', 'Migration can only be executed safely on "mysql".');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization ADD accesstoken VARCHAR(5000) NOT NULL COLLATE utf8mb4_unicode_ci, ADD refreshtoken VARCHAR(5000) DEFAULT NULL COLLATE utf8mb4_unicode_ci, ADD expires DATETIME DEFAULT NULL COMMENT \'(DC2Type:datetime_immutable)\', ADD tokenvalues LONGTEXT NOT NULL COLLATE utf8mb4_unicode_ci COMMENT \'(DC2Type:array)\', DROP serializedaccesstoken');
    }
}
