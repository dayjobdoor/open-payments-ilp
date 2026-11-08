/** Deterministic xorshift32 so fuzz corpora are reproducible without wall-clock or Math.random. */
export function prng(seed: number): () => number {
  let state = seed >>> 0 || 1;

  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;

    return state;
  };
}

/**
 * A reproducible stand-in for `randomBytes`: each call returns the next `length` bytes of one stream drawn from
 * `seed`, so a failing run can be replayed. Not for anything but test secrets, nonces and payloads.
 */
export function byteSource(seed: number): (length: number) => Uint8Array<ArrayBuffer> {
  const next = prng(seed);

  return (length) => Uint8Array.from({ length }, () => next() & 0xff);
}

/** `count` single-byte mutations of `bytes` (flip, replace, truncate, insert anywhere) drawn from `seed`. */
export function mutations(bytes: Uint8Array, count: number, seed: number): Uint8Array[] {
  const next = prng(seed);
  const out: Uint8Array[] = [];

  for (let i = 0; i < count; i++) {
    const copy = Uint8Array.from(bytes);
    const kind = next() % 4;
    const at = next() % Math.max(copy.length, 1);

    if (kind === 0) copy[at] = (copy[at] ?? 0) ^ (1 << (next() % 8));
    else if (kind === 1) copy[at] = next() & 0xff;
    else if (kind === 2) out.push(copy.slice(0, at));
    else {
      // Insert at any position, the end included, which shifts every later length and frame boundary.
      const position = next() % (copy.length + 1);
      out.push(Uint8Array.of(...copy.subarray(0, position), next() & 0xff, ...copy.subarray(position)));
    }

    if (kind < 2) out.push(copy);
  }

  return out;
}
