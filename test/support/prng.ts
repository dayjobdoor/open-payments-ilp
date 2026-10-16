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

/** `count` single-byte mutations of `bytes` (flip, replace, truncate, extend) drawn from `seed`. */
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
    else out.push(Uint8Array.of(...copy, next() & 0xff));

    if (kind < 2) out.push(copy);
  }

  return out;
}
