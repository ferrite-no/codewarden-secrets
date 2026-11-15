// The Action's post step: runs at the end of the job, also after a
// failure, and removes the files the main step wrote (design §32.22).

import * as core from "@actions/core";
import { rm } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

async function run(): Promise<void> {
  const dir = core.getState("dir");
  const base = process.env.RUNNER_TEMP;
  if (!dir || !base) {
    return;
  }
  // Only the directory the main step made.
  if (dirname(resolve(dir)) !== resolve(base) || !basename(dir).startsWith("codewarden-secrets-")) {
    core.warning("codewarden-secrets: the saved directory is not ours; nothing removed");
    return;
  }
  await rm(dir, { recursive: true, force: true });
  core.info("codewarden-secrets: removed the secret files");
}

run().catch((err: unknown) => {
  core.warning(err instanceof Error ? err.message : "codewarden-secrets: cleanup failed");
});
