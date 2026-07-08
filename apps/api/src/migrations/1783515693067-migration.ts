/*
 * Copyright Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

import { MigrationInterface, QueryRunner } from 'typeorm'

// 0G patch: per-port public access — nullable allowlist column; null keeps
// today's all-or-nothing `public` semantics for existing sandboxes.
export class Migration1783515693067 implements MigrationInterface {
  name = 'Migration1783515693067'

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "sandbox" ADD "publicPorts" jsonb`)
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "sandbox" DROP COLUMN "publicPorts"`)
  }
}
