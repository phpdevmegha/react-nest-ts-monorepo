"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Init1768545468168 = void 0;
class Init1768545468168 {
    name = 'Init1768545468168';
    async up(queryRunner) {
        await queryRunner.query(`ALTER TABLE "users" ADD "password" character varying`);
        await queryRunner.query(`UPDATE "users" SET "password" = '' WHERE "password" IS NULL`);
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "password" SET NOT NULL`);
    }
    async down(queryRunner) {
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "password"`);
    }
}
exports.Init1768545468168 = Init1768545468168;
//# sourceMappingURL=1768545468168-init.js.map