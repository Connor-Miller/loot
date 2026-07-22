/**
 * RelayTransport (#432) — the narrow **dumb-pipe** the relay `LootRepo` adapter
 * POSTs through instead of calling `fetch` directly. It does **only** the
 * network: one `post(endpoint, body)` that returns the raw `{ status, body }`
 * (a connection failure throws). Every interpretation — 200 → decode, 401 →
 * `AuthError`, other/throw → `TransportError`, path-scoping, compose — stays in
 * the adapter, so those branches are unit-testable against a fake transport with
 * no live `loot serve`.
 */

/** The raw outcome of a relay POST: the HTTP status and the response body bytes. */
export interface RelayResponse {
  status: number;
  body: Uint8Array;
}

export interface RelayTransport {
  /** POST `body` to `endpoint` (e.g. `/fetch`, `/stow`, `/negotiate`) and return
   * the raw status + body. A connection failure (relay unreachable) throws; a
   * non-2xx response resolves with its status for the adapter to classify. */
  post(endpoint: string, body: Uint8Array): Promise<RelayResponse>;
}

/** The default {@link RelayTransport}: a plain `fetch` POST at `url + endpoint`. */
export class HttpRelayTransport implements RelayTransport {
  constructor(private readonly url: string) {}

  async post(endpoint: string, body: Uint8Array): Promise<RelayResponse> {
    const resp = await fetch(`${this.url}${endpoint}`, {
      method: "POST",
      body,
      headers: { "content-type": "application/octet-stream" },
    });
    return { status: resp.status, body: new Uint8Array(await resp.arrayBuffer()) };
  }
}
