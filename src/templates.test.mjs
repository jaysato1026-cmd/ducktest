import test from "node:test";
import assert from "node:assert/strict";
import { TEST_TEMPLATES, getTemplate } from "./templates.mjs";

test("ships repeatable test templates", () => {
  assert.ok(Object.keys(TEST_TEMPLATES).length >= 4);
  assert.equal(getTemplate("spike").mode, "spike");
  assert.equal(getTemplate("unknown").method, "GET");
});
