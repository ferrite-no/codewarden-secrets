// The calls to CodeWarden: the token exchange (RFC 8693) and the secrets
// API (design §32.7, §32.21). Values travel only in POST answers.

export const tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
export const jwtType = "urn:ietf:params:oauth:token-type:jwt";
export const accessTokenType = "urn:ietf:params:oauth:token-type:access_token";
/** The public client a job names at /token: its ID token is the credential. */
export const workloadClient = "codewarden-workload";

export interface SecretMeta {
  id: string;
  name: string;
  fields?: { name: string; type: string }[];
}

/** One field's value: text, or bytes for a binary field. */
export interface FieldValue {
  name: string;
  text?: string;
  bytes?: Buffer;
}

async function call(url: string, init: RequestInit): Promise<unknown> {
  const res = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(30_000) });
  const body = await res.text();
  if (!res.ok) {
    // Only the status and the fixed error code: never the body otherwise.
    let code = "";
    try {
      const j = JSON.parse(body) as { error?: unknown; error_reason?: unknown };
      code = [j.error, j.error_reason].filter((x) => typeof x === "string").join(", ");
    } catch {
      // not JSON
    }
    throw new Error(`codewarden-secrets: ${new URL(url).pathname} answered ${res.status}${code ? " (" + code + ")" : ""}`);
  }
  return JSON.parse(body);
}

/** Exchanges the job's ID token for a short secrets token. */
export async function exchange(server: string, resource: string, idToken: string): Promise<string> {
  const form = new URLSearchParams({
    grant_type: tokenExchange,
    client_id: workloadClient,
    subject_token: idToken,
    subject_token_type: jwtType,
    requested_token_type: accessTokenType,
    resource,
    scope: "secrets.read secrets.use",
  });
  const out = (await call(server + "/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: form,
  })) as { access_token?: unknown; issued_token_type?: unknown };
  if (typeof out.access_token !== "string" || out.issued_token_type !== accessTokenType) {
    throw new Error("codewarden-secrets: the exchange answered no access token");
  }
  return out.access_token;
}

function auth(token: string): Record<string, string> {
  return { Authorization: "Bearer " + token, Accept: "application/json" };
}

/** The secrets the token reaches. */
export async function list(server: string, token: string): Promise<SecretMeta[]> {
  const out = (await call(server + "/secrets/v1/secrets", { headers: auth(token) })) as { secrets?: SecretMeta[] };
  return out.secrets ?? [];
}

/** Reads every field of a secret, or one. */
export async function read(server: string, token: string, id: string, field?: string): Promise<FieldValue[]> {
  const out = (await call(server + "/secrets/v1/secrets/" + encodeURIComponent(id) + "/value", {
    method: "POST",
    headers: { ...auth(token), "Content-Type": "application/json" },
    body: JSON.stringify(field ? { field } : {}),
  })) as {
    field?: string;
    value?: string;
    value_base64?: string;
    fields?: Record<string, string>;
    fields_base64?: Record<string, string>;
  };
  if (field) {
    if (typeof out.value === "string") {
      return [{ name: field, text: out.value }];
    }
    if (typeof out.value_base64 === "string") {
      return [{ name: field, bytes: Buffer.from(out.value_base64, "base64") }];
    }
    throw new Error("codewarden-secrets: the read answered no value");
  }
  const vals: FieldValue[] = [];
  for (const [name, text] of Object.entries(out.fields ?? {})) {
    vals.push({ name, text });
  }
  for (const [name, b64] of Object.entries(out.fields_base64 ?? {})) {
    vals.push({ name, bytes: Buffer.from(b64, "base64") });
  }
  return vals.sort((a, b) => (a.name < b.name ? -1 : 1));
}

/** Finds a secret by name or "id:<uuid>" among those the token reaches. */
export function resolve(secrets: SecretMeta[], ref: string): SecretMeta {
  const hits = ref.startsWith("id:") ? secrets.filter((s) => s.id === ref.slice(3)) : secrets.filter((s) => s.name === ref);
  if (hits.length !== 1) {
    throw new Error(
      hits.length === 0
        ? `codewarden-secrets: no secret "${ref}" is shared with this job; check the rule on the secret's page`
        : `codewarden-secrets: several secrets are named "${ref}"; write id:<uuid>`,
    );
  }
  return hits[0]!;
}
