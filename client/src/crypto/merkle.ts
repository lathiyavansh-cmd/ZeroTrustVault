// SHA-256 Merkle tree with 0x00 leaf / 0x01 node prefixes, odd nodes promoted — identical to merkle.py
import { concat, sha256 } from "./encoding";

const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

export function leafHash(ct: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(LEAF, ct));
}
export function nodeHash(l: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(NODE, l, r));
}

export async function merkleRootFromLeaves(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) throw new Error("merkle tree needs at least one leaf");
  let level = leaves.slice();
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(await nodeHash(level[i], level[i + 1]));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

export async function merkleRoot(chunks: Uint8Array[]): Promise<Uint8Array> {
  const leaves: Uint8Array[] = [];
  for (const c of chunks) leaves.push(await leafHash(c));
  return merkleRootFromLeaves(leaves);
}
