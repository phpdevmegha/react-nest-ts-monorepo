import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init1768545468168 implements MigrationInterface {
  name = 'Init1768545468168';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" ADD "password" character varying`,
    );
    await queryRunner.query(
      `UPDATE "users" SET "password" = '' WHERE "password" IS NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE "users" ALTER COLUMN "password" SET NOT NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "password"`);
  }
}
