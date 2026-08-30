// CarProof web verifier — core crypto (no DOM). Works in the browser and in Node 18+.
// Uses only WebCrypto (crypto.subtle). Mirrors verifier/verify.py and the iOS app.

export function hexToBytes(hex) {
  const clean = hex.length % 2 ? "0" + hex : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// RFC 6962 Merkle Tree Hash: leaf = SHA256(0x00||d), node = SHA256(0x01||l||r).
export async function merkleRoot(leaves) {
  const n = leaves.length;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return sha256(concat(Uint8Array.of(0x00), leaves[0]));
  let k = 1;
  while ((k << 1) < n) k <<= 1;
  const left = await merkleRoot(leaves.slice(0, k));
  const right = await merkleRoot(leaves.slice(k));
  return sha256(concat(Uint8Array.of(0x01), left, right));
}

export async function merkleRootHexFromDescriptors(descriptors) {
  const enc = new TextEncoder();
  return bytesToHex(await merkleRoot(descriptors.map((d) => enc.encode(d))));
}

// ECDSA DER signature → raw r||s (64 bytes) for WebCrypto.
export function derEcdsaToRaw(der) {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error("signature is not a DER SEQUENCE");
  let seqLen = der[i++];
  if (seqLen & 0x80) {
    const nb = seqLen & 0x7f; seqLen = 0;
    for (let j = 0; j < nb; j++) seqLen = (seqLen << 8) | der[i++];
  }
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error("expected INTEGER in signature");
    const len = der[i++];
    let val = der.slice(i, i + len); i += len;
    while (val.length > 1 && val[0] === 0x00) val = val.slice(1); // strip sign padding
    return val;
  };
  const r = readInt(), s = readInt();
  const pad = (b) => { const o = new Uint8Array(32); o.set(b, 32 - b.length); return o; };
  return concat(pad(r), pad(s));
}

// ECDSA-P256 verify: signature over the 32-byte root, hashed with SHA-256 before signing.
export async function verifySignature(rootBytes, signatureHex, publicKeyHex) {
  const pub = hexToBytes(publicKeyHex);
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error("public_key is not an uncompressed P-256 point");
  }
  const key = await crypto.subtle.importKey(
    "raw", pub, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );
  const rawSig = derEcdsaToRaw(hexToBytes(signatureHex));
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, rawSig, rootBytes);
}

// RFC 3161: locate the SHA-256 messageImprint (SEQUENCE{OID sha256,NULL} then OCTET STRING(32)).
const IMPRINT_PATTERN = [
  0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  0x05, 0x00, 0x04, 0x20,
];
export function parseTimestampImprintHex(tsr) {
  outer: for (let i = 0; i + IMPRINT_PATTERN.length + 32 <= tsr.length; i++) {
    for (let j = 0; j < IMPRINT_PATTERN.length; j++) {
      if (tsr[i + j] !== IMPRINT_PATTERN[j]) continue outer;
    }
    return bytesToHex(tsr.slice(i + IMPRINT_PATTERN.length, i + IMPRINT_PATTERN.length + 32));
  }
  return null;
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out;
}

// Per-photo composite hash: SHA256(jpeg || 0x7C7C || metadata.json).
// photoFiles: { basename: Uint8Array }. Returns { total, verified, missing }.
async function verifyPhotoHashes(descriptors, photoFiles) {
  let total = 0, verified = 0, missing = 0;
  for (const d of descriptors) {
    const p = d.split("|");
    if (p.length < 6 || p[0] !== "photo") continue;
    total++;
    const [, pid, phase, ptype, , stated] = p;
    const stem = `${phase}-${ptype}-${pid}`;
    const jpg = photoFiles[`${stem}.jpg`];
    const meta = photoFiles[`${stem}.meta.json`];
    if (!jpg || !meta) { missing++; continue; }
    const h = bytesToHex(await sha256(concatBytes(jpg, Uint8Array.of(0x7c, 0x7c), meta)));
    if (h === stated.toLowerCase()) verified++;
  }
  return { total, verified, missing };
}

// Verify a parsed bundle. Returns a structured report (no DOM, no throwing on logic failures).
// photoFiles (optional): { "<phase>-<type>-<id>.jpg": Uint8Array, "....meta.json": Uint8Array }.
export async function verifyBundle({ evidenceManifest, manifest, timestampBytes, photoFiles = {} }) {
  const report = { checks: [], verified: false };
  const add = (ok, label, detail = "") => report.checks.push({ ok, label, detail });

  if (!evidenceManifest || !Array.isArray(evidenceManifest.leaves)) {
    add(false, "evidence-manifest.json missing or invalid");
    return report;
  }
  const descriptors = evidenceManifest.leaves.map((l) => l.descriptor);
  const statedRoot = (evidenceManifest.merkle_root || "").toLowerCase();
  const recomputed = await merkleRootHexFromDescriptors(descriptors);

  if (recomputed === statedRoot) {
    add(true, `Merkle root matches (${descriptors.length} leaves, RFC 6962)`, recomputed);
  } else {
    add(false, "Merkle root MISMATCH", `stated ${statedRoot} / recomputed ${recomputed}`);
  }

  const trust = (manifest && manifest.trust_anchors) || {};
  if (trust.device_signature && trust.public_key) {
    try {
      const ok = await verifySignature(hexToBytes(statedRoot), trust.device_signature, trust.public_key);
      add(ok, ok ? "Device signature valid (ECDSA-P256 over SHA-256(root))" : "Device signature INVALID");
    } catch (e) {
      add(false, "Signature check error", String(e.message || e));
    }
  } else {
    add(false, "No device_signature/public_key (report not finalized?)");
  }

  const ph = await verifyPhotoHashes(descriptors, photoFiles);
  if (ph.total > 0 && ph.verified === ph.total) {
    add(true, `Per-photo hashes verified (${ph.verified}/${ph.total})`, "SHA256(jpeg||0x7C7C||meta)");
  } else if (ph.total > 0 && ph.missing === ph.total) {
    add(true, `Per-photo files not loaded (${ph.missing}) — root still covers them`, "optional");
  } else if (ph.total > 0) {
    add(false, `Per-photo hash check: ${ph.verified}/${ph.total} ok, ${ph.missing} missing`);
  }

  if (timestampBytes && timestampBytes.length) {
    const imprint = parseTimestampImprintHex(timestampBytes);
    if (imprint === statedRoot) {
      add(true, "Trusted timestamp commits to root", "RFC 3161 token present");
    } else {
      add(false, "Timestamp imprint != root", String(imprint));
    }
  } else {
    add(true, "No timestamp.tsr (trusted timestamp not enabled)", "optional");
  }

  report.verified = report.checks.every((c) => c.ok);
  return report;
}
