// The Action's main step (design §32.22): the job's OIDC token for
// CodeWarden's secrets resource, exchanged for a short secrets token; the
// secrets read, every value masked first, then exported as variables or
// 0600 files the post step removes.

import * as core from "@actions/core";
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { exchange, read, type FieldValue } from "./client.js";
import { binaryMaskPieces, fieldVariable, maskPieces, parseSpecs, secretIDs } from "./spec.js";

interface Exported {
  name: string;
  secret: string;
  field: string;
  file: boolean;
}

function mask(v: FieldValue): void {
  const pieces = v.text !== undefined ? maskPieces(v.text) : binaryMaskPieces(v.bytes!);
  for (const p of pieces) {
    core.setSecret(p);
  }
}

async function run(): Promise<void> {
  const specs = parseSpecs(core.getInput("secrets", { required: true }));
  const server = core.getInput("server").replace(/\/+$/, "") || "https://id.ferrite.no";
  if (!server.startsWith("https://")) {
    throw new Error("codewarden-secrets: the server must be https");
  }
  const resource = server + "/secrets";
  const idToken = await core.getIDToken(resource);
  core.setSecret(idToken);
  // The token reaches exactly the secrets named, by ID.
  const token = await exchange(server, resource, idToken, secretIDs(specs));
  core.setSecret(token);

  // Read everything and mask every value before a single one is exported.
  const reads: { spec: (typeof specs)[number]; values: FieldValue[] }[] = [];
  for (const spec of specs) {
    const values = await read(server, token, spec.secret, spec.field);
    values.forEach(mask);
    reads.push({ spec, values });
  }

  // Every name is decided, and checked once, before anything is exported.
  const plan: { name: string; secret: string; file: boolean; v: FieldValue }[] = [];
  const names = new Set<string>();
  for (const { spec, values } of reads) {
    for (const v of values) {
      const name = spec.field !== undefined ? spec.name : fieldVariable(spec.name, v.name);
      if (names.has(name)) {
        throw new Error(`codewarden-secrets: two lines of "secrets" export ${name}; rename one with NAME=`);
      }
      names.add(name);
      plan.push({ name, secret: spec.secret, file: spec.file, v });
    }
  }

  let dir = "";
  const exported: Exported[] = [];
  for (const { name, secret, file, v } of plan) {
    if (file) {
      if (dir === "") {
        const base = process.env.RUNNER_TEMP;
        if (!base) {
          throw new Error("codewarden-secrets: RUNNER_TEMP is not set; files need it");
        }
        dir = await mkdtemp(join(base, "codewarden-secrets-"));
        core.saveState("dir", dir);
      }
      const path = join(dir, name);
      // A binary field's raw bytes; a text field's UTF-8.
      await writeFile(path, v.bytes ?? v.text ?? "", { mode: 0o600, flag: "wx" });
      core.exportVariable(name, path);
    } else {
      core.exportVariable(name, v.text ?? v.bytes!.toString("base64"));
    }
    exported.push({ name, secret, field: v.name, file });
  }
  if (core.getBooleanInput("export-token")) {
    core.exportVariable("CODEWARDEN_TOKEN", token);
  }
  core.setOutput("exported", JSON.stringify(exported));
  core.info(`codewarden-secrets: exported ${exported.map((e) => e.name).join(", ")}`);
}

run().catch((err: unknown) => {
  core.setFailed(err instanceof Error ? err.message : "codewarden-secrets: failed");
});
