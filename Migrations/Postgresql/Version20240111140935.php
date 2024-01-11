<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Add Authorization table
 */
final class Version20240111140935 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add Authorization table';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\PostgreSQL94Platform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\PostgreSQL94Platform'."
        );

        $this->addSql('CREATE TABLE flownative_oauth2_client_authorization (authorizationid VARCHAR(255) NOT NULL, servicename VARCHAR(255) NOT NULL, clientid VARCHAR(255) NOT NULL, granttype VARCHAR(255) NOT NULL, scope VARCHAR(255) NOT NULL, expires TIMESTAMP(0) WITHOUT TIME ZONE DEFAULT NULL, serializedaccesstoken TEXT DEFAULT NULL, encryptedserializedaccesstoken TEXT DEFAULT NULL, metadata TEXT DEFAULT NULL, PRIMARY KEY(authorizationid))');
        $this->addSql('COMMENT ON COLUMN flownative_oauth2_client_authorization.expires IS \'(DC2Type:datetime_immutable)\'');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\PostgreSQL94Platform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\PostgreSQL94Platform'."
        );

        $this->addSql('DROP TABLE flownative_oauth2_client_authorization');
    }
}
