<?php
declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Platforms\MySQLPlatform;
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
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof MySQLPlatform), 'Migration can only be executed safely on \'mysql\'.');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization CHANGE scope scope LONGTEXT NOT NULL');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!($this->connection->getDatabasePlatform() instanceof MySQLPlatform), 'Migration can only be executed safely on \'mysql\'.');

        $this->addSql('ALTER TABLE flownative_oauth2_client_authorization CHANGE scope scope VARCHAR(255) NOT NULL');
    }
}
