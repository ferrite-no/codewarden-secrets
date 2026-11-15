import { strict as assert } from "node:assert";
import { test } from "node:test";

import { resolve } from "../src/client.js";
import { binaryMaskPieces, maskPieces, parseSpecs } from "../src/spec.js";

test("parses one field, a whole secret, a prefix and files", () => {
  assert.deepEqual(parseSpecs("ASC_P8=asc#p8\nasc\nAWS=aws-deploy\nfile:KEY=asc#p8\n# a comment\n\nid:0b6a4f1e-5f46-4ab2-9c01-000000000001#token"), [
    { secret: "asc", field: "p8", name: "ASC_P8", file: false },
    { secret: "asc", name: "ASC", file: false },
    { secret: "aws-deploy", name: "AWS", file: false },
    { secret: "asc", field: "p8", name: "KEY", file: true },
    { secret: "id:0b6a4f1e-5f46-4ab2-9c01-000000000001", field: "token", name: "0B6A4F1E_5F46_4AB2_9C01_000000000001_TOKEN".replace(/^/, "_"), file: false },
  ]);
  assert.deepEqual(parseSpecs("prod/stripe.key#api_key"), [{ secret: "prod/stripe.key", field: "api_key", name: "PROD_STRIPE_KEY_API_KEY", file: false }]);
});

test("refuses lines that do not read and names that would overwrite the runner's", () => {
  for (const bad of ["", "asc#P8", "asc#", "a b", "lower=asc", "GITHUB_TOKEN=asc#p8", "RUNNER_TEMP=asc", "CODEWARDEN_TOKEN=asc", "X=bad name#f"]) {
    assert.throws(() => parseSpecs(bad), /secrets/);
  }
});

test("masks the whole value and each line of a multi-line one", () => {
  const pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----\n";
  const pieces = maskPieces(pem);
  assert.ok(pieces.includes(pem));
  assert.ok(pieces.includes("MIGHAgEAMBMG"));
  assert.ok(pieces.includes("-----BEGIN PRIVATE KEY-----"));
  assert.ok(!pieces.includes(""));
  assert.deepEqual(maskPieces("   "), []);
});

test("resolves a secret by name or ID, and only one", () => {
  const list = [
    { id: "0b6a4f1e-5f46-4ab2-9c01-000000000001", name: "asc" },
    { id: "0b6a4f1e-5f46-4ab2-9c01-000000000002", name: "dup" },
    { id: "0b6a4f1e-5f46-4ab2-9c01-000000000003", name: "dup" },
  ];
  assert.equal(resolve(list, "asc").id, list[0]!.id);
  assert.equal(resolve(list, "id:" + list[2]!.id).name, "dup");
  assert.throws(() => resolve(list, "dup"), /several/);
  assert.throws(() => resolve(list, "nope"), /no secret/);
});

test("masks a binary value's base64, and its lines when it is text", () => {
  const pem = Buffer.from("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----\n");
  const pieces = binaryMaskPieces(pem);
  assert.ok(pieces.includes(pem.toString("base64")));
  assert.ok(pieces.includes("MIGHAgEAMBMG"));
  const p12 = Buffer.from([0x30, 0x82, 0xff, 0xfe, 0x00, 0x01, 0x02, 0x03]);
  assert.deepEqual(binaryMaskPieces(p12), [p12.toString("base64")]);
});
