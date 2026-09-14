<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Allow scopes longer than 255 characters on Authorization table
 */
final class Version20260914132449 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Allow scopes longer than 255 characters on Authorization table';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform,
            'Migration can only be executed safely on "postgresql".'
        );

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization ALTER scope TYPE TEXT');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform,
            'Migration can only be executed safely on "postgresql".'
        );

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization ALTER scope TYPE VARCHAR(255)');
    }
}
