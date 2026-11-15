import { strict as assert } from "node:assert";
import { test } from "node:test";

import { exchangeForm } from "../src/client.js";
import { binaryMaskPieces, maskPieces, parseSpecs, secretIDs } from "../src/spec.js";

const A = "0b6a4f1e-5f46-4ab2-9c01-000000000001";
const B = "0b6a4f1e-5f46-4ab2-9c01-000000000002";

test("parses NAME=id#field, NAME=id and files", () => {
  assert.deepEqual(parseSpecs(`ASC_P8=${A}#p8\nASC=${A}\nfile:KEY=${A}#p8\n# a comment\n\nAWS=${B.toUpperCase()}`), [
    { secret: A, field: "p8", name: "ASC_P8", file: false },
    { secret: A, name: "ASC", file: false },
    { secret: A, field: "p8", name: "KEY", file: true },
    { secret: B, name: "AWS", file: false },
  ]);
});

test("refuses a secret named by name, or by id: prefix", () => {
  for (const bad of ["ASC_P8=asc#p8", "AWS=aws-deploy", "X=prod/stripe.key#api_key", `X=id:${A}#p8`, `X=${A}x#p8`]) {
    assert.throws(() => parseSpecs(bad), /named by ID/);
  }
});

test("refuses a bare secret: no name to export it as", () => {
  for (const bad of [A, `${A}#p8`, `file:${A}#p8`, "asc"]) {
    assert.throws(() => parseSpecs(bad), /names no variable/);
  }
});

test("refuses lines that do not read and names that would overwrite the runner's", () => {
  for (const bad of ["", `X=${A}#P8`, `X=${A}#`, `lower=${A}`, `GITHUB_TOKEN=${A}#p8`, `RUNNER_TEMP=${A}`, `CODEWARDEN_TOKEN=${A}`]) {
    assert.throws(() => parseSpecs(bad), /secrets/);
  }
});

test("secret_ids holds each ID once, in order, and at most 20", () => {
  const specs = parseSpecs(`P8=${A}#p8\nK=${A}#key_id\nX=${B}\nfile:F=${A}#p8`);
  assert.deepEqual(secretIDs(specs), [A, B]);
  assert.equal(exchangeForm("https://id.example.com/secrets", "tok", secretIDs(specs)).get("secret_ids"), `${A} ${B}`);
  const many = Array.from({ length: 21 }, (_, i) => `V${i}=0b6a4f1e-5f46-4ab2-9c01-${String(i).padStart(12, "0")}`).join("\n");
  assert.throws(() => parseSpecs(many), /more than 20/);
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

test("masks a binary value's base64, and its lines when it is text", () => {
  const pem = Buffer.from("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----\n");
  const pieces = binaryMaskPieces(pem);
  assert.ok(pieces.includes(pem.toString("base64")));
  assert.ok(pieces.includes("MIGHAgEAMBMG"));
  const p12 = Buffer.from([0x30, 0x82, 0xff, 0xfe, 0x00, 0x01, 0x02, 0x03]);
  assert.deepEqual(binaryMaskPieces(p12), [p12.toString("base64")]);
});
