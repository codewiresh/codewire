import assert from "node:assert/strict";
import test from "node:test";
import type postgres from "postgres";
import { TEST_PASSWORD } from "./seed";
import { seedSyntheticIdentity, TEST_PASSWORD_HASH } from "./synthetic-users";

test("synthetic identity seeding rejects non-e2e addresses before database access", async () => {
  let databaseCalls = 0;
  const sql = {
    begin: async () => {
      databaseCalls += 1;
    },
  } as unknown as postgres.Sql;

  await assert.rejects(
    seedSyntheticIdentity(sql, "owner@example.com", "Owner"),
    /Refusing to seed a non-synthetic dashboard identity/,
  );
  assert.equal(databaseCalls, 0);
});

test("the fixed synthetic hash authenticates the canonical test password", async () => {
  const runtime = globalThis as typeof globalThis & {
    Bun: {
      password: {
        verify(password: string, hash: string): Promise<boolean>;
      };
    };
  };

  assert.equal(await runtime.Bun.password.verify(TEST_PASSWORD, TEST_PASSWORD_HASH), true);
  assert.equal(await runtime.Bun.password.verify(`${TEST_PASSWORD}wrong`, TEST_PASSWORD_HASH), false);
});
