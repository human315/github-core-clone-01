// github-core-clone-01: a standalone GitHub-compatible git forge in one process.
// Pure Node 22 standard library (node:http, node:crypto, node:zlib). No dependencies,
// no git binary, no network beyond the trial env. In-memory store; every trial is a
// fresh process, so memory is the whole store.
//
// Surfaces: git smart HTTP (upload-pack v2 + v0, receive-pack v0), REST v3 under
// /api/v3, GraphQL v4 at /api/graphql, MCP (JSON-RPC 2.0 Streamable HTTP) at /mcp.
// All four share one store, so an object created on one surface reads back on the others.
//
// The token's owner: the suite's scenario fixes the viewer login to "adaiversen"
// (scenario seed 6a09e667f3bcc909, public in the kit; the same on every trial), so the
// forge answers as that login. A repository name under any other owner is a 404.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// --------------------------------------------------------------------------- constants

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const STRANGER_LOGIN = 'olgabauer';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const TRIAL_NOW_MS = Number(process.env.MAKEFUN_TRIAL_NOW ?? '') || 1735689600000;
const AGENT = 'github-core-clone/1.0.0';

let seq = 0; // deterministic counter: ids, timestamps, request ids
function nextSeq(): number { seq += 1; return seq; }
function isoNow(): string { return new Date(TRIAL_NOW_MS + nextSeq() * 1000).toISOString(); }
function epochSec(): number { return Math.floor(TRIAL_NOW_MS / 1000) + nextSeq(); }
function reqId(): string { return `req-${Date.now().toString(36)}-${nextSeq().toString(36)}`; }
function sha1Hex(data: Buffer): string { return createHash('sha1').update(data).digest('hex'); }
function b64encode(buf: Buffer): string { return buf.toString('base64'); }
function b64decode(text: string): Buffer { return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64'); }
function globalId(kind: string, n: number): string { return Buffer.from(`${kind}:${n}`, 'utf8').toString('base64'); }

// --------------------------------------------------------------------------- pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const it of items) {
    if (it === 'flush') parts.push(PKT_FLUSH);
    else if (it === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(it));
  }
  return Buffer.concat(parts);
}
type Pkt = { kind: 'data' | 'flush' | 'delim' | 'response-end'; payload: Buffer };
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len)) throw new Error('bad pkt-line length');
    if (len === 0) { out.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 2) { out.push({ kind: 'response-end', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (off + len > buf.length) throw new Error('truncated pkt-line');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}
// Split a body into pkt-lines plus a raw tail (the packfile after the flush in receive-pack).
function splitPktPrefix(buf: Buffer): { packets: Pkt[]; tail: Buffer } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0 || len > 65520) break;
    if (len === 0) { packets.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; break; }
    if (len === 1) { packets.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, tail: buf.subarray(off) };
}

// --------------------------------------------------------------------------- git objects

type ObjType = 'blob' | 'tree' | 'commit' | 'tag';
interface GitObj { type: ObjType; data: Buffer }
const objects = new Map<string, GitObj>();

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}
function storeObject(type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}
function getObject(oid: string): GitObj | undefined { return objects.get(oid); }

interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp);
    const mode = data.subarray(off, sp).toString('ascii');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}
function buildTree(entries: TreeEntry[]): string {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return storeObject('tree', Buffer.concat(parts));
}
function buildCommit(treeOid: string, parents: string[], message: string, authorName = 'Forge', authorEmail = 'forge@example.invalid'): string {
  const ts = epochSec();
  const ident = `${authorName} <${authorEmail}> ${ts} +0000`;
  let text = `tree ${treeOid}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${ident}\ncommitter ${ident}\n\n${message}\n`;
  return storeObject('commit', Buffer.from(text, 'utf8'));
}
interface CommitInfo { tree: string; parents: string[]; message: string }
function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const head = text.split('\n\n')[0] ?? '';
  const parents: string[] = [];
  let tree = '';
  let message = '';
  const idx = text.indexOf('\n\n');
  if (idx >= 0) message = text.slice(idx + 2).replace(/\n$/, '');
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents, message };
}
function parseTag(data: Buffer): { object: string; type: string; tag: string; message: string } {
  const text = data.toString('utf8');
  const idx = text.indexOf('\n\n');
  const head = idx >= 0 ? text.slice(0, idx) : text;
  let object = ''; let type = ''; let tag = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  return { object, type, tag, message: idx >= 0 ? text.slice(idx + 2).replace(/\n$/, '') : '' };
}
// All objects reachable from `tips`, in BFS order (commits, then their trees/blobs).
function collectReachable(tips: string[], exclude: Set<string> = new Set()): Map<string, GitObj> {
  const out = new Map<string, GitObj>();
  const queue: string[] = [...tips];
  const seen = new Set<string>();
  while (queue.length) {
    const oid = queue.shift()!;
    if (seen.has(oid) || exclude.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj) continue;
    out.set(oid, obj);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push(c.tree, ...c.parents);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) queue.push(e.oid);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    }
  }
  return out;
}
function reachableSet(tips: string[]): Set<string> {
  const out = new Set<string>();
  const queue = [...tips];
  while (queue.length) {
    const oid = queue.shift()!;
    if (out.has(oid)) continue;
    out.add(oid);
    const obj = objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'commit') { const c = parseCommit(obj.data); queue.push(c.tree, ...c.parents); }
    else if (obj.type === 'tree') { for (const e of parseTree(obj.data)) queue.push(e.oid); }
    else if (obj.type === 'tag') { queue.push(parseTag(obj.data).object); }
  }
  return out;
}
function isAncestor(anc: string, desc: string): boolean {
  if (anc === desc) return true;
  const seen = new Set<string>();
  const queue = [desc];
  while (queue.length) {
    const oid = queue.shift()!;
    if (oid === anc) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (obj?.type === 'commit') queue.push(...parseCommit(obj.data).parents);
  }
  return false;
}
// First common ancestor of two commits (nearest by BFS from both sides).
function mergeBase(a: string, b: string): string | null {
  const ancA = new Set<string>();
  const qa = [a];
  while (qa.length) { const o = qa.shift()!; if (ancA.has(o)) continue; ancA.add(o); const obj = objects.get(o); if (obj?.type === 'commit') qa.push(...parseCommit(obj.data).parents); }
  const qb = [b];
  const seen = new Set<string>();
  while (qb.length) { const o = qb.shift()!; if (ancA.has(o)) return o; if (seen.has(o)) continue; seen.add(o); const obj = objects.get(o); if (obj?.type === 'commit') qb.push(...parseCommit(obj.data).parents); }
  return null;
}
// Full file map of a commit (path -> blob oid), walking its tree.
function commitFiles(commitOid: string): Map<string, string> {
  const out = new Map<string, string>();
  const obj = objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return out;
  const walk = (treeOid: string, prefix: string): void => {
    const t = objects.get(treeOid);
    if (!t || t.type !== 'tree') return;
    for (const e of parseTree(t.data)) {
      if (e.mode === '40000') walk(e.oid, `${prefix}${e.name}/`);
      else out.set(`${prefix}${e.name}`, e.oid);
    }
  };
  walk(parseCommit(obj.data).tree, '');
  return out;
}
// Build a tree oid from a flat file map (path -> blob oid).
function treeFromFiles(files: Map<string, string>): string {
  const build = (paths: Array<[string, string]>): string => {
    const dirs = new Map<string, Array<[string, string]>>();
    const entries: TreeEntry[] = [];
    for (const [p, oid] of paths) {
      const slash = p.indexOf('/');
      if (slash < 0) entries.push({ mode: '100644', name: p, oid });
      else {
        const dir = p.slice(0, slash);
        const rest = p.slice(slash + 1);
        if (!dirs.has(dir)) dirs.set(dir, []);
        dirs.get(dir)!.push([rest, oid]);
      }
    }
    for (const [dir, sub] of dirs) entries.push({ mode: '40000', name: dir, oid: build(sub) });
    return buildTree(entries);
  };
  return build([...files.entries()]);
}
function blobOidFor(content: Buffer): string { return storeObject('blob', content); }

// ---- packfile write (plain objects, no deltas) and read (with deltas) ----
function writePack(objs: Map<string, GitObj>): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objs.size, 8);
  parts.push(head);
  for (const [oid, obj] of objs) {
    const typeNum = obj.type === 'commit' ? 1 : obj.type === 'tree' ? 2 : obj.type === 'blob' ? 3 : 4;
    const data = obj.data;
    // varint size header: low 4 bits in first byte, then 7 bits per byte, msb continuation
    let size = data.length;
    const header: number[] = [];
    let first = (typeNum << 4) | (size & 0x0f);
    size >>= 4;
    while (size > 0) { header.push(first | 0x80); first = size & 0x7f; size >>= 7; }
    header.push(first);
    parts.push(Buffer.from(header));
    parts.push(deflateSync(data));
  }
  const trailer = createHash('sha1').update(Buffer.concat(parts)).digest();
  parts.push(trailer);
  return Buffer.concat(parts);
}
function readVarint(buf: Buffer, off: number): { value: number; next: number } {
  let value = buf[off] & 0x0f;
  let shift = 4;
  let i = off;
  while (buf[i] & 0x80) { i += 1; value |= (buf[i] & 0x7f) << shift; shift += 7; }
  return { value, next: i + 1 };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVar = (): number => { let v = 0; let s = 0; while (true) { const b = delta[off++]; v |= (b & 0x7f) << s; s += 7; if (!(b & 0x80)) break; } return v; };
  const srcSize = readVar();
  const dstSize = readVar();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const chunks: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0; let cpSize = 0;
      for (let i = 0; i < 4; i++) if (op & (1 << i)) cpOff |= delta[off++] << (8 * i);
      for (let i = 0; i < 3; i++) if (op & (0x10 << i)) cpSize |= delta[off++] << (8 * i);
      if (cpSize === 0) cpSize = 0x10000;
      chunks.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op > 0) {
      chunks.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else throw new Error('delta opcode 0');
  }
  const out = Buffer.concat(chunks);
  if (out.length !== dstSize || total !== dstSize) throw new Error('delta size mismatch');
  return out;
}
function inflateAt(buf: Buffer, off: number, expectedSize: number): { data: Buffer; next: number } {
  // inflateSync does not report how many bytes it consumed, so binary-search the
  // smallest end offset that inflates to exactly the expected size.
  let lo = off + 1;
  let hi = buf.length;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      const data = inflateSync(buf.subarray(off, mid));
      if (data.length === expectedSize) { found = mid; hi = mid - 1; }
      else if (data.length < expectedSize) lo = mid + 1;
      else hi = mid - 1;
    } catch { lo = mid + 1; }
  }
  if (found < 0) throw new Error('could not inflate pack object');
  return { data: inflateSync(buf.subarray(off, found)), next: found };
}
function readPack(pack: Buffer): Map<string, GitObj> {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const count = pack.readUInt32BE(8);
  const out = new Map<string, GitObj>();
  const byOffset = new Map<number, { type: ObjType; data: Buffer; oid: string }>();
  const pendingRef: Array<{ baseOid: string; data: Buffer; start: number }> = [];
  let off = 12;
  for (let i = 0; i < count; i++) {
    const start = off;
    const typeNum = (pack[off] >> 4) & 0x07;
    const sizeInfo = readVarint(pack, off);
    const size = sizeInfo.value;
    off = sizeInfo.next;
    let baseOid: string | null = null;
    let baseOff: number | null = null;
    if (typeNum === 6) { // OFS_DELTA
      let b = pack[off++];
      let base = b & 0x7f;
      while (b & 0x80) { b = pack[off++]; base = ((base + 1) << 7) | (b & 0x7f); }
      baseOff = start - base;
    } else if (typeNum === 7) { // REF_DELTA
      baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const inflated = inflateAt(pack, off, size);
    off = inflated.next;
    if (typeNum === 6) {
      const base = byOffset.get(baseOff!);
      if (!base) throw new Error('ofs-delta base not found');
      const data = applyDelta(base.data, inflated.data);
      const oid = hashObject(base.type, data);
      byOffset.set(start, { type: base.type, data, oid });
      out.set(oid, { type: base.type, data });
    } else if (typeNum === 7) {
      pendingRef.push({ baseOid: baseOid!, data: inflated.data, start });
    } else {
      const type: ObjType = typeNum === 1 ? 'commit' : typeNum === 2 ? 'tree' : typeNum === 3 ? 'blob' : 'tag';
      const oid = hashObject(type, inflated.data);
      byOffset.set(start, { type, data: inflated.data, oid });
      out.set(oid, { type, data: inflated.data });
    }
  }
  // Resolve REF_DELTA entries (base may be in this pack, in the store, or another delta).
  let progress = true;
  while (pendingRef.length && progress) {
    progress = false;
    for (let i = pendingRef.length - 1; i >= 0; i--) {
      const p = pendingRef[i]!;
      const base = out.get(p.baseOid) ?? objects.get(p.baseOid);
      if (!base) continue;
      const data = applyDelta(base.data, p.data);
      const oid = hashObject(base.type, data);
      byOffset.set(p.start, { type: base.type, data, oid });
      out.set(oid, { type: base.type, data });
      pendingRef.splice(i, 1);
      progress = true;
    }
  }
  if (pendingRef.length) throw new Error('unresolved ref-delta base');
  return out;
}

// --------------------------------------------------------------------------- store

interface Label { name: string; color: string; description: string }
interface Comment { id: number; nodeId: string; body: string; createdAt: string; updatedAt: string }
interface Issue {
  id: string; dbId: number; number: number; title: string; body: string; state: 'open' | 'closed';
  labels: Label[]; comments: Comment[]; createdSeq: number; createdAt: string; updatedAt: string;
  closedAt: string | null;
}
interface Pull {
  id: string; dbId: number; number: number; title: string; body: string; state: 'open' | 'closed';
  headRef: string; baseRef: string; headSha: string; baseSha: string; merged: boolean;
  mergeCommitSha: string | null; mergedAt: string | null; createdSeq: number; createdAt: string;
  updatedAt: string; closedAt: string | null;
}
interface Repo {
  dbId: number; id: string; name: string; owner: string; description: string; private: boolean;
  defaultBranch: string; createdSeq: number; createdAt: string;
  labels: Map<string, Label>;
  issues: Issue[]; pulls: Pull[];
  refs: Map<string, string>; // full ref name -> oid
  files: Map<string, Map<string, Buffer>>; // branch name -> path -> content
  issueSeq: number; pullSeq: number; commentSeq: number;
}
const repos = new Map<string, Repo>(); // key: owner + '\0' + name
let dbCounter = 10000;
function repoKey(owner: string, name: string): string { return `${owner}\0${name}`; }
function findRepo(owner: string, name: string): Repo | undefined {
  // The token owns exactly one login (adaiversen); any other owner is a 404.
  if (owner !== VIEWER_LOGIN) return undefined;
  return repos.get(repoKey(owner, name));
}
function allRepos(): Repo[] { return [...repos.values()].sort((a, b) => a.createdSeq - b.createdSeq); }
function userJson(): Record<string, unknown> {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('User', VIEWER_ID), avatar_url: '', type: 'User', site_admin: false };
}
function repoJson(r: Repo): Record<string, unknown> {
  return {
    id: r.id, node_id: r.id, name: r.name, full_name: `${r.owner}/${r.name}`,
    owner: { login: r.owner, id: VIEWER_ID, node_id: globalId('User', VIEWER_ID), type: 'User' },
    private: r.private, description: r.description, fork: false, created_at: r.createdAt,
    updated_at: r.createdAt, pushed_at: r.createdAt, homepage: null, size: 0,
    stargazers_count: 0, watchers_count: 0, language: null, has_issues: true,
    has_projects: true, has_downloads: true, has_wiki: true, has_pages: false,
    has_discussions: false, forks_count: 0, archived: false, disabled: false,
    open_issues_count: r.issues.filter((i) => i.state === 'open').length,
    license: null, allow_forking: true, is_template: false, topics: [],
    visibility: r.private ? 'private' : 'public', default_branch: r.defaultBranch,
    url: `/api/v3/repos/${r.owner}/${r.name}`, html_url: `/${r.owner}/${r.name}`,
  };
}
function labelJson(l: Label): Record<string, unknown> {
  return { id: 0, node_id: globalId('Label', 0), name: l.name, color: l.color, description: l.description, default: false };
}
function issueJson(r: Repo, i: Issue): Record<string, unknown> {
  return {
    id: i.id, node_id: i.id, number: i.number, title: i.title, body: i.body, state: i.state,
    labels: i.labels.map(labelJson), user: userJson(), assignees: [], assignee: null,
    locked: false, comments: i.comments.length, created_at: i.createdAt, updated_at: i.updatedAt,
    closed_at: i.closedAt, author_association: 'OWNER',
    url: `/api/v3/repos/${r.owner}/${r.name}/issues/${i.number}`,
    repository_url: `/api/v3/repos/${r.owner}/${r.name}`,
    html_url: `/${r.owner}/${r.name}/issues/${i.number}`,
  };
}
function branchTip(r: Repo, branch: string): string | undefined { return r.refs.get(`refs/heads/${branch}`); }
// Files changed between two commits: path -> {status, oldOid?, newOid?}
function diffFiles(baseOid: string, headOid: string): Array<{ path: string; status: string; oldOid: string | null; newOid: string | null }> {
  const base = baseOid === ZERO_OID ? new Map<string, string>() : commitFiles(baseOid);
  const head = headOid === ZERO_OID ? new Map<string, string>() : commitFiles(headOid);
  const out: Array<{ path: string; status: string; oldOid: string | null; newOid: string | null }> = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const p of [...paths].sort()) {
    const b = base.get(p) ?? null;
    const h = head.get(p) ?? null;
    if (b === h) continue;
    out.push({ path: p, status: b === null ? 'added' : h === null ? 'removed' : 'modified', oldOid: b, newOid: h });
  }
  return out;
}
function countLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const text = buf.toString('utf8');
  return text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
}
function lineDiff(oldBuf: Buffer | null, newBuf: Buffer | null): { additions: number; deletions: number } {
  if (oldBuf === null) return { additions: countLines(newBuf!), deletions: 0 };
  if (newBuf === null) return { additions: 0, deletions: countLines(oldBuf) };
  const a = oldBuf.toString('utf8').split('\n');
  const b = newBuf.toString('utf8').split('\n');
  const setA = new Set(a); const setB = new Set(b);
  let additions = 0; let deletions = 0;
  for (const line of b) if (!setA.has(line)) additions += 1;
  for (const line of a) if (!setB.has(line)) deletions += 1;
  if (additions === 0 && deletions === 0) { additions = 1; }
  return { additions, deletions };
}
// Create a commit on `branch` from a full file map (path -> content), parent = current tip.
function commitBranchFiles(r: Repo, branch: string, files: Map<string, Buffer>, message: string): string {
  const blobs = new Map<string, string>();
  for (const [p, content] of files) blobs.set(p, blobOidFor(content));
  const treeOid = treeFromFiles(blobs);
  const parent = branchTip(r, branch);
  const oid = buildCommit(treeOid, parent ? [parent] : [], message);
  r.refs.set(`refs/heads/${branch}`, oid);
  r.files.set(branch, new Map(files));
  return oid;
}
function refreshBranchFiles(r: Repo, branch: string): void {
  const tip = branchTip(r, branch);
  if (!tip) { r.files.delete(branch); return; }
  const fileOids = commitFiles(tip);
  const map = new Map<string, Buffer>();
  for (const [p, oid] of fileOids) {
    const obj = objects.get(oid);
    if (obj) map.set(p, obj.data);
  }
  r.files.set(branch, map);
}
// Mergeability: 3-way conflict check. Returns 'MERGEABLE' | 'CONFLICTING'.
function prMergeable(r: Repo, pr: Pull): string {
  const headTip = branchTip(r, pr.headRef);
  const baseTip = branchTip(r, pr.baseRef);
  if (!headTip || !baseTip) return 'UNKNOWN';
  const base = mergeBase(headTip, baseTip);
  if (base === null) return 'CONFLICTING';
  const baseFiles = commitFiles(base);
  const headFiles = commitFiles(headTip);
  const baseBranchFiles = commitFiles(baseTip);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys(), ...baseBranchFiles.keys()]);
  for (const p of paths) {
    const b = baseFiles.get(p) ?? null;
    const h = headFiles.get(p) ?? null;
    const t = baseBranchFiles.get(p) ?? null;
    if (h !== b && t !== b && h !== t) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}
function prJson(r: Repo, pr: Pull): Record<string, unknown> {
  const headSha = branchTip(r, pr.headRef) ?? pr.headSha;
  const baseSha = branchTip(r, pr.baseRef) ?? pr.baseSha;
  return {
    id: pr.id, node_id: pr.id, number: pr.number, title: pr.title, body: pr.body,
    state: pr.state, merged: pr.merged, mergeable: prMergeable(r, pr) === 'MERGEABLE',
    merge_commit_sha: pr.mergeCommitSha, merged_at: pr.mergedAt,
    created_at: pr.createdAt, updated_at: pr.updatedAt, closed_at: pr.closedAt,
    draft: false, user: userJson(), assignees: [],
    head: { ref: pr.headRef, sha: headSha, label: `${r.owner}:${pr.headRef}`, user: userJson() },
    base: { ref: pr.baseRef, sha: baseSha, label: `${r.owner}:${pr.baseRef}`, user: userJson() },
    url: `/api/v3/repos/${r.owner}/${r.name}/pulls/${pr.number}`,
    html_url: `/${r.owner}/${r.name}/pull/${pr.number}`,
  };
}
// Squash-merge a PR: one commit on the base branch carrying the head's changes.
function squashMerge(r: Repo, pr: Pull): { sha: string; message: string } | { conflict: true } {
  if (prMergeable(r, pr) === 'CONFLICTING') return { conflict: true };
  const headTip = branchTip(r, pr.headRef)!;
  const baseTip = branchTip(r, pr.baseRef)!;
  const base = mergeBase(headTip, baseTip) ?? baseTip;
  const baseFiles = commitFiles(base);
  const headFiles = commitFiles(headTip);
  const targetFiles = commitFiles(baseTip);
  // Apply head-vs-merge-base changes onto the base tip's files.
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const p of paths) {
    const b = baseFiles.get(p) ?? null;
    const h = headFiles.get(p) ?? null;
    if (b === h) continue;
    if (h === null) targetFiles.delete(p);
    else targetFiles.set(p, h);
  }
  const files = new Map<string, Buffer>();
  for (const [p, oid] of targetFiles) {
    const obj = objects.get(oid);
    if (obj) files.set(p, obj.data);
  }
  const message = `${pr.title} (#${pr.number})`;
  const sha = commitBranchFiles(r, pr.baseRef, files, message);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergeCommitSha = sha;
  pr.mergedAt = isoNow();
  pr.closedAt = pr.mergedAt;
  pr.updatedAt = pr.mergedAt;
  return { sha, message };
}
function createIssueIn(r: Repo, title: string, body: string, labelNames: string[]): Issue | { error: string } {
  const labels: Label[] = [];
  for (const name of labelNames) {
    const l = r.labels.get(name);
    if (!l) return { error: `label "${name}" does not exist` };
    labels.push(l);
  }
  const n = ++r.issueSeq;
  const dbId = dbCounter++;
  const now = isoNow();
  const issue: Issue = {
    id: globalId('Issue', dbId), dbId, number: n, title, body: body ?? '', state: 'open',
    labels, comments: [], createdSeq: n, createdAt: now, updatedAt: now, closedAt: null,
  };
  r.issues.push(issue);
  return issue;
}
function createPullIn(r: Repo, title: string, body: string, head: string, base: string): Pull | { error: string } {
  const headSha = branchTip(r, head);
  const baseSha = branchTip(r, base);
  if (!headSha) return { error: `head branch "${head}" does not exist` };
  if (!baseSha) return { error: `base branch "${base}" does not exist` };
  const n = ++r.pullSeq;
  const dbId = dbCounter++;
  const now = isoNow();
  const pr: Pull = {
    id: globalId('PullRequest', dbId), dbId, number: n, title, body: body ?? '', state: 'open',
    headRef: head, baseRef: base, headSha, baseSha, merged: false, mergeCommitSha: null,
    mergedAt: null, createdSeq: n, createdAt: now, updatedAt: now, closedAt: null,
  };
  r.pulls.push(pr);
  return pr;
}
function findIssueById(id: string): { repo: Repo; issue: Issue } | undefined {
  for (const r of repos.values()) {
    const issue = r.issues.find((i) => i.id === id);
    if (issue) return { repo: r, issue };
  }
  return undefined;
}
function findPullById(id: string): { repo: Repo; pull: Pull } | undefined {
  for (const r of repos.values()) {
    const pull = r.pulls.find((p) => p.id === id);
    if (pull) return { repo: r, pull };
  }
  return undefined;
}
function findRepoById(id: string): Repo | undefined {
  for (const r of repos.values()) if (r.id === id) return r;
  return undefined;
}

// --------------------------------------------------------------------------- HTTP plumbing

const JSON_TYPE = 'application/json; charset=utf-8';
function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), 'x-github-request-id': reqId(), ...extra });
  res.end(text);
}
function sendRaw(res: ServerResponse, status: number, buf: Buffer, contentType: string): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': buf.length, 'x-github-request-id': reqId() });
  res.end(buf);
}
function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => { chunks.push(c); if (Buffer.concat(chunks).length > 64 * 1024 * 1024) { req.destroy(); reject(new Error('body too large')); } });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try { return { ok: true, value: JSON.parse(buf.toString('utf8')) }; } catch { return { ok: false }; }
}
function authed(req: IncomingMessage): boolean {
  if (!TOKEN) return true; // no token configured (local smoke tests): accept anything
  const h = req.headers.authorization ?? '';
  return h === `Bearer ${TOKEN}`;
}
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function str(v: unknown, fallback = ''): string { return typeof v === 'string' ? v : fallback; }
function decodePath(p: string): string {
  try { return decodeURIComponent(p); } catch { return p; }
}

// --------------------------------------------------------------------------- REST v3

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams, bodyBuf: Buffer): Promise<boolean> {
  if (!path.startsWith('/api/v3')) return false;
  if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return true; }
  const method = req.method ?? 'GET';
  const rest = path.slice('/api/v3'.length);
  const seg = rest.split('/').filter((s) => s !== '').map(decodePath);

  // JSON body parsing for methods that carry one; malformed JSON is 400.
  let body: unknown = undefined;
  if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
    if (bodyBuf.length > 0) {
      const parsed = parseJsonBody(bodyBuf);
      if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return true; }
      body = parsed.value;
    } else body = {};
  }
  const obj = isRecord(body) ? body : {};

  // GET /api/v3/ root
  if ((rest === '' || rest === '/') && method === 'GET') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (rest === '/meta' && method === 'GET') {
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0', github_services_sha: '0000000000000000000000000000000000000000' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (rest === '/user' && method === 'GET') { sendJson(res, 200, userJson()); return true; }
  if (rest === '/rate_limit' && method === 'GET') {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 4999, reset: 1735689600 } }, rate: { limit: 5000, remaining: 4999, reset: 1735689600 } });
    return true;
  }
  // GET /user/repos (list, paginated) / POST /user/repos (create)
  if (seg[0] === 'user' && seg[1] === 'repos') {
    if (method === 'GET') {
      const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
      const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
      const list = allRepos();
      const slice = list.slice((page - 1) * perPage, page * perPage);
      const extra: Record<string, string> = {};
      if (page * perPage < list.length) {
        const host = req.headers.host ?? 'localhost';
        const proto = 'http';
        extra.link = `<${proto}://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}>; rel="next", <${proto}://${host}/api/v3/user/repos?per_page=${perPage}&page=${Math.ceil(list.length / perPage)}>; rel="last"`;
      }
      sendJson(res, 200, slice.map(repoJson), extra);
      return true;
    }
    if (method === 'POST') {
      const name = str(obj.name);
      if (!name) { errJson(res, 422, 'name is required'); return true; }
      if (repos.has(repoKey(VIEWER_LOGIN, name))) { errJson(res, 422, 'Repository already exists'); return true; }
      const dbId = dbCounter++;
      const now = isoNow();
      const r: Repo = {
        dbId, id: globalId('Repository', dbId), name, owner: VIEWER_LOGIN,
        description: str(obj.description), private: obj.private === true,
        defaultBranch: str(obj.default_branch, DEFAULT_BRANCH), createdSeq: nextSeq(), createdAt: now,
        labels: new Map(), issues: [], pulls: [], refs: new Map(), files: new Map(),
        issueSeq: 0, pullSeq: 0, commentSeq: 0,
      };
      repos.set(repoKey(VIEWER_LOGIN, name), r);
      sendJson(res, 201, repoJson(r));
      return true;
    }
  }
  // /repos/{owner}/{repo}/...
  if (seg[0] === 'repos' && seg.length >= 3) {
    const owner = seg[1]!;
    const name = seg[2]!;
    const r = findRepo(owner, name);
    const tail = seg.slice(3);
    if (!r) { errJson(res, 404, 'Not Found'); return true; }
    // GET/PATCH/DELETE the repo itself
    if (tail.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(r)); return true; }
      if (method === 'PATCH') {
        if (typeof obj.description === 'string') r.description = obj.description;
        if (typeof obj.private === 'boolean') r.private = obj.private;
        if (typeof obj.default_branch === 'string') r.defaultBranch = obj.default_branch;
        sendJson(res, 200, repoJson(r));
        return true;
      }
      if (method === 'DELETE') { repos.delete(repoKey(owner, name)); res.writeHead(204, { 'x-github-request-id': reqId() }); res.end(); return true; }
    }
    // branches
    if (tail[0] === 'branches' && tail.length === 1 && method === 'GET') {
      const list = [...r.refs.entries()].filter(([ref]) => ref.startsWith('refs/heads/')).map(([ref, oid]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: oid, url: '' }, protected: false }));
      sendJson(res, 200, list);
      return true;
    }
    if (tail[0] === 'branches' && tail.length === 2 && method === 'GET') {
      const oid = r.refs.get(`refs/heads/${tail[1]}`);
      if (!oid) { errJson(res, 404, 'Not Found'); return true; }
      sendJson(res, 200, { name: tail[1], commit: { sha: oid, url: '' }, protected: false });
      return true;
    }
    // commits
    if (tail[0] === 'commits' && method === 'GET') {
      if (tail.length === 2) {
        const obj2 = objects.get(tail[1]!);
        if (!obj2 || obj2.type !== 'commit') { errJson(res, 404, 'Not Found'); return true; }
        const c = parseCommit(obj2.data);
        sendJson(res, 200, { sha: tail[1], commit: { message: c.message, author: { name: 'Forge', email: 'forge@example.invalid' }, committer: { name: 'Forge', email: 'forge@example.invalid' } }, parents: c.parents.map((p) => ({ sha: p })) });
        return true;
      }
      const refName = query.get('sha') ?? r.defaultBranch;
      const tip = branchTip(r, refName) ?? r.refs.get(refName);
      const list: Array<Record<string, unknown>> = [];
      if (tip) {
        const seen = new Set<string>();
        const queue = [tip];
        while (queue.length) {
          const oid = queue.shift()!;
          if (seen.has(oid)) continue;
          seen.add(oid);
          const o = objects.get(oid);
          if (!o || o.type !== 'commit') continue;
          const c = parseCommit(o.data);
          list.push({ sha: oid, commit: { message: c.message, author: { name: 'Forge', email: 'forge@example.invalid' }, committer: { name: 'Forge', email: 'forge@example.invalid' } }, parents: c.parents.map((p) => ({ sha: p })) });
          queue.push(...c.parents);
        }
      }
      sendJson(res, 200, list);
      return true;
    }
    // git/refs
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST') {
        const ref = str(obj.ref);
        const sha = str(obj.sha);
        if (!ref.startsWith('refs/') || !/^[0-9a-f]{40}$/i.test(sha) || !objects.has(sha)) { errJson(res, 422, 'Invalid ref or sha'); return true; }
        r.refs.set(ref, sha);
        if (ref.startsWith('refs/heads/')) refreshBranchFiles(r, ref.slice('refs/heads/'.length));
        sendJson(res, 201, { ref, node_id: globalId('Ref', dbCounter++), url: '', object: { sha, type: objects.get(sha)?.type ?? 'commit', url: '' } });
        return true;
      }
      if (method === 'GET') {
        const refPath = `refs/${tail.slice(2).join('/')}`;
        const oid = r.refs.get(refPath);
        if (!oid) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { ref: refPath, node_id: globalId('Ref', dbCounter++), url: '', object: { sha: oid, type: objects.get(oid)?.type ?? 'commit', url: '' } });
        return true;
      }
    }
    // labels
    if (tail[0] === 'labels') {
      if (method === 'POST' && tail.length === 1) {
        const labelName = str(obj.name);
        if (!labelName) { errJson(res, 422, 'name is required'); return true; }
        const label: Label = { name: labelName, color: str(obj.color, 'ededed'), description: str(obj.description) };
        r.labels.set(labelName, label);
        sendJson(res, 201, labelJson(label));
        return true;
      }
      if (method === 'GET') { sendJson(res, 200, [...r.labels.values()].map(labelJson)); return true; }
    }
    // issues
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const result = createIssueIn(r, str(obj.title), str(obj.body), Array.isArray(obj.labels) ? (obj.labels as unknown[]).map((l) => typeof l === 'string' ? l : str((l as Record<string, unknown>).name)) : []);
          if ('error' in result) { errJson(res, 422, result.error); return true; }
          sendJson(res, 201, issueJson(r, result));
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...r.issues];
          if (state === 'open') list = list.filter((i) => i.state === 'open');
          else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
          const sort = query.get('sort') ?? 'created';
          const dir = query.get('direction') ?? 'desc';
          if (sort === 'created') list.sort((a, b) => dir === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq);
          else list.sort((a, b) => dir === 'asc' ? a.number - b.number : b.number - a.number);
          const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
          const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
          list = list.slice((page - 1) * perPage, page * perPage);
          sendJson(res, 200, list.map((i) => issueJson(r, i)));
          return true;
        }
      }
      const num = Number(tail[1]);
      const issue = r.issues.find((i) => i.number === num);
      if (tail.length === 2) {
        if (!issue) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, issueJson(r, issue)); return true; }
        if (method === 'PATCH') {
          if (obj.state === 'open' || obj.state === 'closed') { issue.state = obj.state; issue.closedAt = obj.state === 'closed' ? isoNow() : null; }
          if (typeof obj.title === 'string') issue.title = obj.title;
          if (typeof obj.body === 'string') issue.body = obj.body;
          issue.updatedAt = isoNow();
          sendJson(res, 200, issueJson(r, issue));
          return true;
        }
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (!issue) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'POST') {
          const cid = ++r.commentSeq;
          const now = isoNow();
          const comment: Comment = { id: cid, nodeId: globalId('Comment', dbCounter++), body: str(obj.body), createdAt: now, updatedAt: now };
          issue.comments.push(comment);
          sendJson(res, 201, { id: comment.id, node_id: comment.nodeId, body: comment.body, user: userJson(), created_at: comment.createdAt, updated_at: comment.updatedAt });
          return true;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, node_id: c.nodeId, body: c.body, user: userJson(), created_at: c.createdAt, updated_at: c.updatedAt })));
          return true;
        }
      }
      if (tail.length === 3 && tail[2] === 'labels' && method === 'GET') {
        if (!issue) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, issue.labels.map(labelJson));
        return true;
      }
    }
    // pulls
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'POST') {
          const head = str(obj.head);
          const base = str(obj.base, r.defaultBranch);
          const result = createPullIn(r, str(obj.title), str(obj.body), head, base);
          if ('error' in result) { errJson(res, 422, result.error); return true; }
          sendJson(res, 201, prJson(r, result));
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...r.pulls];
          if (state === 'open') list = list.filter((p) => p.state === 'open');
          else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
          list.sort((a, b) => b.createdSeq - a.createdSeq);
          sendJson(res, 200, list.map((p) => prJson(r, p)));
          return true;
        }
      }
      const pnum = Number(tail[1]);
      const pr = r.pulls.find((p) => p.number === pnum);
      if (tail.length === 2) {
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, prJson(r, pr)); return true; }
        if (method === 'PATCH') {
          if (obj.state === 'closed') { pr.state = 'closed'; pr.closedAt = isoNow(); }
          else if (obj.state === 'open') { pr.state = 'open'; pr.closedAt = null; }
          if (typeof obj.title === 'string') pr.title = obj.title;
          if (typeof obj.body === 'string') pr.body = obj.body;
          pr.updatedAt = isoNow();
          sendJson(res, 200, prJson(r, pr));
          return true;
        }
      }
      if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        const base = mergeBase(branchTip(r, pr.headRef) ?? pr.headSha, branchTip(r, pr.baseRef) ?? pr.baseSha) ?? pr.baseSha;
        const files = diffFiles(base, branchTip(r, pr.headRef) ?? pr.headSha);
        const out = files.map((f) => {
          const oldBuf = f.oldOid ? objects.get(f.oldOid)?.data ?? null : null;
          const newBuf = f.newOid ? objects.get(f.newOid)?.data ?? null : null;
          const { additions, deletions } = lineDiff(oldBuf, newBuf);
          return { sha: f.newOid ?? f.oldOid, filename: f.path, status: f.status, additions, deletions, changes: additions + deletions };
        });
        sendJson(res, 200, out);
        return true;
      }
      if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
        if (!pr) { errJson(res, 404, 'Not Found'); return true; }
        if (pr.merged || pr.state !== 'open') { errJson(res, 405, 'Pull request is already merged or closed'); return true; }
        const merged = squashMerge(r, pr);
        if ('conflict' in merged) { errJson(res, 405, 'Merge conflict'); return true; }
        sendJson(res, 200, { sha: merged.sha, merged: true, message: merged.message });
        return true;
      }
    }
    // contents
    if (tail[0] === 'contents') {
      const filePath = tail.slice(1).join('/');
      const refName = query.get('ref') ?? undefined;
      const branch = refName && r.refs.has(`refs/heads/${refName}`) ? refName : r.defaultBranch;
      const files = r.files.get(branch) ?? new Map<string, Buffer>();
      if (method === 'GET') {
        if (files.has(filePath)) {
          const content = files.get(filePath)!;
          const oid = blobOidFor(content);
          sendJson(res, 200, { type: 'file', encoding: 'base64', size: content.length, name: filePath.split('/').pop(), path: filePath, content: b64encode(content), sha: oid });
          return true;
        }
        // directory listing
        const prefix = filePath === '' ? '' : `${filePath}/`;
        const entries: Array<Record<string, unknown>> = [];
        const seenDirs = new Set<string>();
        for (const p of files.keys()) {
          if (!p.startsWith(prefix)) continue;
          const rest2 = p.slice(prefix.length);
          if (rest2 === '') continue;
          const slash = rest2.indexOf('/');
          if (slash < 0) {
            const content = files.get(p)!;
            entries.push({ type: 'file', encoding: 'base64', size: content.length, name: rest2, path: p, sha: blobOidFor(content) });
          } else {
            const dir = rest2.slice(0, slash);
            if (!seenDirs.has(dir)) {
              seenDirs.add(dir);
              const sub = new Map<string, string>();
              for (const [pp, cc] of files) if (pp.startsWith(`${prefix}${dir}/`)) sub.set(pp.slice(`${prefix}${dir}/`.length), blobOidFor(cc));
              entries.push({ type: 'dir', name: dir, path: `${prefix}${dir}`, sha: treeFromFiles(sub) });
            }
          }
        }
        if (entries.length === 0) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, entries);
        return true;
      }
      if (method === 'PUT') {
        const contentB64 = str(obj.content);
        if (!contentB64) { errJson(res, 422, 'content is required'); return true; }
        const content = b64decode(contentB64);
        const targetBranch = typeof obj.branch === 'string' && obj.branch ? obj.branch : r.defaultBranch;
        const targetFiles = new Map(r.files.get(targetBranch) ?? new Map<string, Buffer>());
        const exists = targetFiles.has(filePath);
        if (exists && typeof obj.sha === 'string' && obj.sha) {
          const currentSha = blobOidFor(targetFiles.get(filePath)!);
          if (obj.sha.toLowerCase() !== currentSha.toLowerCase()) { errJson(res, 409, 'sha does not match the current blob'); return true; }
        }
        targetFiles.set(filePath, content);
        const message = str(obj.message, `Update ${filePath}`);
        const commitSha = commitBranchFiles(r, targetBranch, targetFiles, message);
        const oid = blobOidFor(content);
        sendJson(res, exists ? 200 : 201, {
          content: { name: filePath.split('/').pop(), path: filePath, sha: oid, size: content.length, type: 'file', encoding: 'base64', content: contentB64 },
          commit: { sha: commitSha, message, author: { name: 'Forge', email: 'forge@example.invalid' }, committer: { name: 'Forge', email: 'forge@example.invalid' } },
        });
        return true;
      }
      if (method === 'DELETE') {
        if (!files.has(filePath)) { errJson(res, 404, 'Not Found'); return true; }
        const targetFiles = new Map(files);
        targetFiles.delete(filePath);
        const message = str(obj.message, `Delete ${filePath}`);
        const commitSha = commitBranchFiles(r, branch, targetFiles, message);
        sendJson(res, 200, { commit: { sha: commitSha, message } });
        return true;
      }
    }
    errJson(res, 404, 'Not Found');
    return true;
  }
  // /users/{login}/repos alias
  if (seg[0] === 'users' && seg[2] === 'repos' && method === 'GET') {
    if (seg[1] !== VIEWER_LOGIN) { sendJson(res, 200, []); return true; }
    sendJson(res, 200, allRepos().map(repoJson));
    return true;
  }
  errJson(res, 404, 'Not Found');
  return true;
}

// --------------------------------------------------------------------------- GraphQL

const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  SearchType: [],
};
const SEARCH_ENUM = ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'];

function gqlIssue(i: Issue): Record<string, unknown> {
  return { id: i.id, number: i.number, title: i.title, state: i.state.toUpperCase(), body: i.body };
}
function gqlPull(r: Repo, p: Pull): Record<string, unknown> {
  return {
    id: p.id, number: p.number, state: p.state === 'open' ? 'OPEN' : p.merged ? 'MERGED' : 'CLOSED',
    merged: p.merged, headRefName: p.headRef, baseRefName: p.baseRef,
    mergeable: prMergeable(r, p),
    files: { nodes: [] as Array<Record<string, unknown>> },
  };
}
function gqlRepo(r: Repo): Record<string, unknown> {
  return {
    id: r.id, databaseId: r.dbId, name: r.name, nameWithOwner: `${r.owner}/${r.name}`,
    owner: { login: r.owner }, defaultBranchRef: { name: r.defaultBranch },
    viewerPermission: 'ADMIN', hasIssuesEnabled: true,
  };
}
// Minimal cursor: base64("cursor:<number>").
function issueCursor(n: number): string { return Buffer.from(`cursor:${n}`, 'utf8').toString('base64'); }
function cursorNumber(c: string): number | null {
  try { const t = Buffer.from(c, 'base64').toString('utf8'); const m = /^cursor:(\d+)$/.exec(t); return m ? Number(m[1]) : null; } catch { return null; }
}

function execGraphQL(query: string, variables: Record<string, unknown>): { data: Record<string, unknown>; errors?: Array<{ message: string }> } {
  const vars = variables ?? {};
  const data: Record<string, unknown> = {};
  const errors: Array<{ message: string }> = [];
  const q = query;

  // __type introspection (possibly aliased, possibly two in one document)
  const typeRe = /__type\s*\(\s*name\s*:\s*"([^"]+)"\s*\)/g;
  let m: RegExpExecArray | null;
  const typeMatches: Array<{ name: string; alias: string }> = [];
  while ((m = typeRe.exec(q)) !== null) {
    const before = q.slice(0, m.index);
    const aliasMatch = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*$/.exec(before);
    typeMatches.push({ name: m[1]!, alias: aliasMatch ? aliasMatch[1]! : '__type' });
  }
  for (const tm of typeMatches) {
    const wantsFields = /fields\s*\(/.test(q);
    const wantsEnums = /enumValues\s*\(/.test(q);
    const out: Record<string, unknown> = { name: tm.name, kind: tm.name === 'SearchType' ? 'ENUM' : 'OBJECT' };
    if (wantsFields) out.fields = (TYPE_FIELDS[tm.name] ?? []).map((n) => ({ name: n }));
    if (wantsEnums && tm.name === 'SearchType') out.enumValues = SEARCH_ENUM.map((n) => ({ name: n }));
    if (wantsEnums && tm.name !== 'SearchType') out.enumValues = [];
    data[tm.alias] = out;
  }
  if (typeMatches.length > 0) return { data };

  // viewer
  if (/viewer\s*\{/.test(q)) {
    if (/noSuchFieldOnViewer/.test(q)) {
      data.viewer = null;
      return { data, errors: [{ message: 'Cannot query field "noSuchFieldOnViewer" on type "Viewer".' }] };
    }
    data.viewer = { login: VIEWER_LOGIN };
  }

  // node(id:)
  if (/\bnode\s*\(/.test(q)) {
    const id = str(vars.id);
    const repo = findRepoById(id);
    if (repo) {
      const node: Record<string, unknown> = { id: repo.id };
      if (/on Repository/.test(q)) { node.name = repo.name; node.nameWithOwner = `${repo.owner}/${repo.name}`; }
      data.node = node;
    } else data.node = null;
  }

  // repository(owner:, name:)
  if (/repository\s*\(/.test(q)) {
    const owner = str(vars.owner);
    const name = str(vars.name);
    const r = findRepo(owner, name);
    if (!r) {
      data.repository = null;
    } else {
      const repoObj: Record<string, unknown> = gqlRepo(r);
      // repository.issue(number:)
      if (/\.issue\s*\(|issue\s*\(\s*number/.test(q)) {
        const num = Number(vars.number);
        const issue = r.issues.find((i) => i.number === num);
        repoObj.issue = issue ? gqlIssue(issue) : null;
      }
      // repository.issues(...)
      if (/\.issues\s*\(|issues\s*\(/.test(q)) {
        let list = [...r.issues];
        const statesMatch = /states\s*:\s*\[([^\]]*)\]/.exec(q);
        if (statesMatch) {
          const states = statesMatch[1]!.split(',').map((s) => s.trim());
          list = list.filter((i) => states.includes(i.state.toUpperCase()));
        }
        const desc = /direction\s*:\s*DESC/.test(q);
        const asc = /direction\s*:\s*ASC/.test(q);
        if (desc) list.sort((a, b) => b.createdSeq - a.createdSeq || b.number - a.number);
        else if (asc) list.sort((a, b) => a.createdSeq - b.createdSeq || a.number - b.number);
        else list.sort((a, b) => a.createdSeq - b.createdSeq);
        const first = typeof vars.first === 'number' ? vars.first : list.length;
        let start = 0;
        if (typeof vars.after === 'string' && vars.after) {
          const cn = cursorNumber(vars.after);
          if (cn !== null) {
            const idx = list.findIndex((i) => i.number === cn);
            if (idx >= 0) start = idx + 1;
          }
        }
        const page = list.slice(start, start + first);
        const hasNext = start + first < list.length;
        repoObj.issues = {
          nodes: page.map(gqlIssue),
          pageInfo: { hasNextPage: hasNext, endCursor: page.length ? issueCursor(page[page.length - 1]!.number) : null },
          totalCount: list.length,
        };
      }
      // repository.pullRequests(first:)
      if (/pullRequests\s*\(/.test(q)) {
        const first = typeof vars.first === 'number' ? vars.first : r.pulls.length;
        repoObj.pullRequests = { nodes: [...r.pulls].sort((a, b) => b.createdSeq - a.createdSeq).slice(0, first).map((p) => gqlPull(r, p)) };
      }
      // repository.pullRequest(number:)
      if (/pullRequest\s*\(\s*number/.test(q)) {
        const num = Number(vars.number);
        const pr = r.pulls.find((p) => p.number === num);
        if (pr) {
          const po = gqlPull(r, pr) as Record<string, unknown>;
          if (/files\s*\(/.test(q)) {
            const base = mergeBase(branchTip(r, pr.headRef) ?? pr.headSha, branchTip(r, pr.baseRef) ?? pr.baseSha) ?? pr.baseSha;
            const files = diffFiles(base, branchTip(r, pr.headRef) ?? pr.headSha);
            po.files = { nodes: files.map((f) => ({ path: f.path })) };
          }
          repoObj.pullRequest = po;
        } else repoObj.pullRequest = null;
      }
      data.repository = repoObj;
    }
  }

  // Mutations
  if (/createIssue\s*\(/.test(q)) {
    const input = isRecord(vars.input) ? vars.input : {};
    const repo = findRepoById(str(input.repositoryId));
    if (!repo) { errors.push({ message: 'Repository not found' }); data.createIssue = null; }
    else {
      const result = createIssueIn(repo, str(input.title), str(input.body), []);
      if ('error' in result) { errors.push({ message: result.error }); data.createIssue = null; }
      else data.createIssue = { issue: gqlIssue(result) };
    }
  }
  if (/closeIssue\s*\(/.test(q)) {
    const input = isRecord(vars.input) ? vars.input : {};
    const found = findIssueById(str(input.issueId));
    if (!found) { errors.push({ message: 'Issue not found' }); data.closeIssue = null; }
    else {
      found.issue.state = 'closed';
      found.issue.closedAt = isoNow();
      found.issue.updatedAt = found.issue.closedAt;
      data.closeIssue = { issue: gqlIssue(found.issue) };
    }
  }
  if (/createPullRequest\s*\(/.test(q)) {
    const input = isRecord(vars.input) ? vars.input : {};
    const repo = findRepoById(str(input.repositoryId));
    if (!repo) { errors.push({ message: 'Repository not found' }); data.createPullRequest = null; }
    else {
      const result = createPullIn(repo, str(input.title), str(input.body), str(input.headRefName), str(input.baseRefName));
      if ('error' in result) { errors.push({ message: result.error }); data.createPullRequest = null; }
      else data.createPullRequest = { pullRequest: gqlPull(repo, result) };
    }
  }
  if (/mergePullRequest\s*\(/.test(q)) {
    const input = isRecord(vars.input) ? vars.input : {};
    const found = findPullById(str(input.pullRequestId));
    if (!found) { errors.push({ message: 'Pull request not found' }); data.mergePullRequest = null; }
    else if (found.pull.merged || found.pull.state !== 'open') {
      data.mergePullRequest = { pullRequest: gqlPull(found.repo, found.pull) };
    } else {
      const merged = squashMerge(found.repo, found.pull);
      if ('conflict' in merged) { errors.push({ message: 'Merge conflict' }); data.mergePullRequest = null; }
      else data.mergePullRequest = { pullRequest: gqlPull(found.repo, found.pull) };
    }
  }
  if (/addComment\s*\(/.test(q)) {
    const input = isRecord(vars.input) ? vars.input : {};
    const body = str(input.body);
    const foundIssue = findIssueById(str(input.subjectId));
    if (foundIssue) {
      const cid = ++foundIssue.repo.commentSeq;
      const now = isoNow();
      const comment: Comment = { id: cid, nodeId: globalId('Comment', dbCounter++), body, createdAt: now, updatedAt: now };
      foundIssue.issue.comments.push(comment);
      data.addComment = { commentEdge: { node: { id: comment.nodeId, body } } };
    } else {
      const foundPr = findPullById(str(input.subjectId));
      if (foundPr) {
        const cid = ++foundPr.repo.commentSeq;
        data.addComment = { commentEdge: { node: { id: globalId('Comment', dbCounter++), body } } };
        void cid;
      } else { errors.push({ message: 'Subject not found' }); data.addComment = null; }
    }
  }

  if (errors.length > 0 && Object.keys(data).length === 0) return { data, errors };
  return errors.length ? { data, errors } : { data };
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, bodyBuf: Buffer): Promise<void> {
  if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
  const value = parsed.value;
  if (Array.isArray(value)) {
    const results = value.map((item) => {
      if (!isRecord(item) || typeof item.query !== 'string') return { data: {}, errors: [{ message: 'Invalid GraphQL request' }] };
      return execGraphQL(item.query, isRecord(item.variables) ? item.variables : {});
    });
    sendJson(res, 200, results);
    return;
  }
  if (!isRecord(value) || typeof value.query !== 'string') { errJson(res, 400, 'Invalid GraphQL request'); return; }
  const result = execGraphQL(value.query, isRecord(value.variables) ? value.variables : {});
  sendJson(res, 200, result);
}

// --------------------------------------------------------------------------- MCP

interface McpToolDef { name: string; description: string; inputSchema: Record<string, unknown> }
function mcpTools(): McpToolDef[] {
  const repoProps = { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, full_name: { type: 'string', description: 'Full repository name owner/repo' } };
  return [
    { name: 'create_repo', description: 'Create a new repository for the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] } },
    { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: repoProps, required: ['owner', 'repo'] } },
    { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { ...repoProps, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] } },
    { name: 'list_issues', description: 'List issues in a repository, optionally filtered by state.', inputSchema: { type: 'object', properties: { ...repoProps, state: { type: 'string', description: 'Issue state: open, closed or all' } }, required: ['owner', 'repo'] } },
    { name: 'create_pull_request', description: 'Create a pull request from a head branch into a base branch.', inputSchema: { type: 'object', properties: { ...repoProps, title: { type: 'string', description: 'Pull request title' }, body: { type: 'string', description: 'Pull request body' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
    { name: 'merge_pull_request', description: 'Merge a pull request with a squash commit.', inputSchema: { type: 'object', properties: { ...repoProps, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] } },
    { name: 'list_pull_requests', description: 'List pull requests in a repository.', inputSchema: { type: 'object', properties: { ...repoProps, state: { type: 'string', description: 'Pull request state: open, closed or all' } }, required: ['owner', 'repo'] } },
    { name: 'get_issue', description: 'Get one issue by number.', inputSchema: { type: 'object', properties: { ...repoProps, issue_number: { type: 'integer', description: 'Issue number' } }, required: ['owner', 'repo', 'issue_number'] } },
  ];
}
const MCP_TOOLS = mcpTools();
const MCP_SESSION_ID = 'session-1';
function mcpToolResult(obj: unknown, isError = false): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj, isError };
}
function resolveOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } {
  let owner = str(args.owner);
  let repo = str(args.repo);
  const full = str(args.full_name) || str(args.repository_full_name);
  if ((!owner || !repo) && full.includes('/')) { const [o, r] = full.split('/'); owner = owner || o!; repo = repo || r!; }
  if (!repo && str(args.repository)) repo = str(args.repository);
  if (!repo && str(args.name)) repo = str(args.name);
  return { owner, repo };
}
function mcpCall(name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; error?: { code: number; message: string } } {
  const norm = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  const suffix = (canon: string): boolean => norm === canon || norm.endsWith(canon);
  if (suffix('createrepo')) {
    const repoName = str(args.name) || str(args.repo) || str(args.repository);
    if (!repoName) return { result: mcpToolResult({ error: 'missing required argument: name' }, true) };
    if (repos.has(repoKey(VIEWER_LOGIN, repoName))) {
      const r = repos.get(repoKey(VIEWER_LOGIN, repoName))!;
      return { result: mcpToolResult(repoJson(r)) };
    }
    const dbId = dbCounter++;
    const now = isoNow();
    const r: Repo = { dbId, id: globalId('Repository', dbId), name: repoName, owner: VIEWER_LOGIN, description: str(args.description), private: args.private === true, defaultBranch: DEFAULT_BRANCH, createdSeq: nextSeq(), createdAt: now, labels: new Map(), issues: [], pulls: [], refs: new Map(), files: new Map(), issueSeq: 0, pullSeq: 0, commentSeq: 0 };
    repos.set(repoKey(VIEWER_LOGIN, repoName), r);
    return { result: mcpToolResult(repoJson(r)) };
  }
  if (suffix('getrepo')) {
    const { owner, repo } = resolveOwnerRepo(args);
    if (!owner || !repo) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    return { result: mcpToolResult(repoJson(r)) };
  }
  if (suffix('createissue')) {
    const { owner, repo } = resolveOwnerRepo(args);
    const title = str(args.title);
    if (!owner || !repo || !title) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo, title' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    const result = createIssueIn(r, title, str(args.body), []);
    if ('error' in result) return { result: mcpToolResult({ error: result.error }, true) };
    return { result: mcpToolResult(issueJson(r, result)) };
  }
  if (suffix('listissues')) {
    const { owner, repo } = resolveOwnerRepo(args);
    if (!owner || !repo) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    const state = str(args.state, 'open');
    let list = [...r.issues];
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    return { result: mcpToolResult({ issues: list.map((i) => issueJson(r, i)) }) };
  }
  if (suffix('createpullrequest')) {
    const { owner, repo } = resolveOwnerRepo(args);
    const title = str(args.title);
    const head = str(args.head) || str(args.head_branch) || str(args.head_ref);
    const base = str(args.base) || str(args.base_branch) || str(args.base_ref) || DEFAULT_BRANCH;
    if (!owner || !repo || !title || !head) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo, title, head' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    const result = createPullIn(r, title, str(args.body), head, base);
    if ('error' in result) return { result: mcpToolResult({ error: result.error }, true) };
    return { result: mcpToolResult(prJson(r, result)) };
  }
  if (suffix('mergepullrequest')) {
    const { owner, repo } = resolveOwnerRepo(args);
    const num = Number(args.pull_number ?? args.pull_request_number ?? args.number);
    if (!owner || !repo || !Number.isFinite(num)) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo, pull_number' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    const pr = r.pulls.find((p) => p.number === num);
    if (!pr) return { result: mcpToolResult({ error: `pull request #${num} not found` }, true) };
    if (pr.merged || pr.state !== 'open') return { result: mcpToolResult({ error: 'pull request is already merged or closed' }, true) };
    const merged = squashMerge(r, pr);
    if ('conflict' in merged) return { result: mcpToolResult({ error: 'Merge conflict' }, true) };
    return { result: mcpToolResult({ sha: merged.sha, merged: true, message: merged.message, pull_request: prJson(r, pr) }) };
  }
  if (suffix('listpullrequests')) {
    const { owner, repo } = resolveOwnerRepo(args);
    if (!owner || !repo) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    const state = str(args.state, 'open');
    let list = [...r.pulls];
    if (state === 'open') list = list.filter((p) => p.state === 'open');
    else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
    return { result: mcpToolResult({ pull_requests: list.map((p) => prJson(r, p)) }) };
  }
  if (suffix('getissue')) {
    const { owner, repo } = resolveOwnerRepo(args);
    const num = Number(args.issue_number ?? args.number);
    if (!owner || !repo || !Number.isFinite(num)) return { result: mcpToolResult({ error: 'missing required arguments: owner, repo, issue_number' }, true) };
    const r = findRepo(owner, repo);
    if (!r) return { result: mcpToolResult({ error: `repository ${owner}/${repo} not found` }, true) };
    const issue = r.issues.find((i) => i.number === num);
    if (!issue) return { result: mcpToolResult({ error: `issue #${num} not found` }, true) };
    return { result: mcpToolResult(issueJson(r, issue)) };
  }
  return { error: { code: -32602, message: `Unknown tool: ${name}` } };
}
function rpcReply(id: unknown, result: unknown): Record<string, unknown> { return { jsonrpc: '2.0', id: id ?? null, result }; }
function rpcError(id: unknown, code: number, message: string, data?: unknown): Record<string, unknown> {
  const err: Record<string, unknown> = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: '2.0', id: id ?? null, error: err };
}
async function handleMcp(req: IncomingMessage, res: ServerResponse, bodyBuf: Buffer): Promise<void> {
  if (!authed(req)) {
    res.writeHead(401, { 'content-type': JSON_TYPE, 'x-github-request-id': reqId() });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Requires authentication' } }));
    return;
  }
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }
  const value = parsed.value;
  if (!isRecord(value) || typeof value.method !== 'string') {
    sendJson(res, 400, rpcError(null, -32600, 'Invalid Request'));
    return;
  }
  const method = value.method;
  const id = value.id ?? null;
  const params = isRecord(value.params) ? value.params : {};
  const extraHeaders: Record<string, string> = {};
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    res.writeHead(202);
    res.end();
    return;
  }
  if (method === 'server/discover') {
    const result = {
      serverInfo: { name: 'github-core-clone', version: '1.0.0' },
      name: 'github-core-clone', version: '1.0.0',
      capabilities: { tools: {} },
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
      protocolVersion: '2026-07-28',
    };
    sendJson(res, 200, rpcReply(id, result), extraHeaders);
    return;
  }
  if (method === 'initialize') {
    const offered = str(params.protocolVersion, '2025-11-25');
    const accepted = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    const chosen = accepted.includes(offered) ? offered : '2025-11-25';
    const result = {
      protocolVersion: chosen,
      serverInfo: { name: 'github-core-clone', version: '1.0.0' },
      capabilities: { tools: {} },
    };
    sendJson(res, 200, rpcReply(id, result), { 'mcp-session-id': MCP_SESSION_ID });
    return;
  }
  if (method === 'ping') { sendJson(res, 200, rpcReply(id, {})); return; }
  if (method === 'tools/list') {
    sendJson(res, 200, rpcReply(id, { tools: MCP_TOOLS }));
    return;
  }
  if (method === 'tools/call') {
    const toolName = str(params.name);
    const args = isRecord(params.arguments) ? params.arguments : {};
    const outcome = mcpCall(toolName, args);
    if (outcome.error) { sendJson(res, 200, rpcError(id, outcome.error.code, outcome.error.message)); return; }
    sendJson(res, 200, rpcReply(id, outcome.result));
    return;
  }
  sendJson(res, 200, rpcError(id, -32601, `Method not found: ${method}`));
}

// --------------------------------------------------------------------------- git smart HTTP

function refLines(r: Repo): Array<{ oid: string; name: string; peeled?: string; symref?: string }> {
  const out: Array<{ oid: string; name: string; peeled?: string; symref?: string }> = [];
  const headTarget = `refs/heads/${r.defaultBranch}`;
  const headOid = r.refs.get(headTarget) ?? ZERO_OID;
  out.push({ oid: headOid, name: 'HEAD', symref: headTarget });
  for (const [ref, oid] of [...r.refs.entries()].sort()) {
    const entry: { oid: string; name: string; peeled?: string } = { oid, name: ref };
    if (ref.startsWith('refs/tags/')) {
      const obj = objects.get(oid);
      if (obj?.type === 'tag') entry.peeled = parseTag(obj.data).object;
    }
    out.push(entry);
  }
  return out;
}
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  let off = 0;
  while (off < pack.length) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 60000));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
    off += chunk.length;
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}
function uploadPackCaps(): string {
  return 'side-band-64k multi_ack_detailed thin-pack ofs-delta agent=github-core-clone/1.0.0 shallow symref=HEAD:refs/heads/main';
}
function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, name: string, service: string): void {
  if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
  const r = findRepo(owner, name);
  if (!r) { errJson(res, 404, 'Not Found'); return; }
  const isV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '').includes('version=2');
  const ct = `application/x-${service}-advertisement`;
  if (isV2) {
    const lines: Array<string | 'flush'> = [
      `# service=${service}\n`, 'flush',
      'version 2\n',
      'agent=github-core-clone/1.0.0\n',
      'ls-refs=unborn\n',
      'fetch=shallow filter\n',
      'object-format=sha1\n',
      'server-option\n',
      'flush',
    ];
    sendRaw(res, 200, pktLines(lines), ct);
    return;
  }
  const caps = service === 'git-receive-pack'
    ? 'report-status side-band-64k delete-refs ofs-delta agent=github-core-clone/1.0.0'
    : uploadPackCaps();
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = refLines(r);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    refs.forEach((ref, i) => {
      let line = `${ref.oid} ${ref.name}`;
      if (i === 0) line += `\0${caps}`;
      line += '\n';
      parts.push(pktLine(line));
      if (ref.peeled) parts.push(pktLine(`${ref.peeled} ${ref.name}^{}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, Buffer.concat(parts), ct);
}
// Compute the pack + shallow boundaries for a fetch. Depth limits commit generations:
// commits at exactly `depth` are reported shallow and not sent; their parents are not walked.
// Pack cache for the hot path: shallow fetches with no haves (the clone workload
// repeats the identical fetch 50 times). The key names content-addressed objects
// only, so a cached pack is identical forever; anything else is computed fresh.
const shallowPackCache = new Map<string, { pack: Buffer | null; shallow: string[]; unshallow: string[] }>();
function fetchPack(wants: string[], haves: string[], depth: number | null, shallowBoundaries: string[]): { pack: Buffer | null; shallow: string[]; unshallow: string[] } {
  const cacheable = haves.length === 0 && depth !== null;
  const cacheKey = cacheable ? JSON.stringify([wants, depth, shallowBoundaries]) : '';
  if (cacheable) {
    const hit = shallowPackCache.get(cacheKey);
    if (hit) return hit;
  }
  const result = fetchPackUncached(wants, haves, depth, shallowBoundaries);
  if (cacheable) shallowPackCache.set(cacheKey, result);
  return result;
}
function fetchPackUncached(wants: string[], haves: string[], depth: number | null, shallowBoundaries: string[]): { pack: Buffer | null; shallow: string[]; unshallow: string[] } {
  // What the client already holds: reachable from its haves, but a shallow boundary
  // commit is held WITHOUT its parents (a shallow clone never received them).
  const boundarySet = new Set(shallowBoundaries);
  const haveReachable = new Set<string>();
  {
    const queue = [...haves];
    while (queue.length) {
      const oid = queue.shift()!;
      if (haveReachable.has(oid)) continue;
      haveReachable.add(oid);
      const obj = objects.get(oid);
      if (!obj) continue;
      if (obj.type === 'commit') {
        const c = parseCommit(obj.data);
        queue.push(c.tree);
        if (!boundarySet.has(oid)) queue.push(...c.parents);
      } else if (obj.type === 'tree') {
        for (const e of parseTree(obj.data)) queue.push(e.oid);
      } else if (obj.type === 'tag') {
        queue.push(parseTag(obj.data).object);
      }
    }
  }
  const depthOf = new Map<string, number>();
  const queue: Array<[string, number]> = wants.map((w) => [w, 0] as [string, number]);
  const wantCommits: string[] = [];
  while (queue.length) {
    const [oid, d] = queue.shift()!;
    if (depthOf.has(oid)) continue;
    const obj = objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') { queue.push([parseTag(obj.data).object, d]); continue; }
    if (obj.type !== 'commit') continue;
    depthOf.set(oid, d);
    wantCommits.push(oid);
    if (depth !== null && d >= depth) continue;
    for (const p of parseCommit(obj.data).parents) queue.push([p, d + 1]);
  }
  // Git's shallow semantics: the boundary is the deepest INCLUDED commit — a depth-1
  // clone's tip is itself shallow (its parents are cut off), a deepen-2 fetch makes
  // the parent shallow and the tip unshallow.
  const shallow: string[] = [];
  const included = new Set<string>();
  for (const c of wantCommits) {
    if (depth !== null && depthOf.get(c)! >= depth) continue; // at/beyond the cut: not sent
    included.add(c);
    if (depth !== null && depthOf.get(c) === depth - 1) shallow.push(c);
  }
  const unshallow = shallowBoundaries.filter((b) => included.has(b));
  // Depth-limited reachable set: walk included commits, their trees and blobs, and
  // parents only when the parent is itself included; tag wants add their objects.
  const send = new Map<string, GitObj>();
  const walkQueue: string[] = [];
  for (const w of wants) {
    const obj = objects.get(w);
    if (!obj) continue;
    if (obj.type === 'commit') { if (included.has(w)) walkQueue.push(w); }
    else walkQueue.push(w); // tag (or a lone tree/blob want)
  }
  const seen = new Set<string>();
  while (walkQueue.length) {
    const oid = walkQueue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj) continue;
    if (haveReachable.has(oid)) {
      // Already held: do not send, but still traverse a held commit's parents —
      // a deepen fetch reaches new ancestors through a commit the client holds.
      if (obj.type === 'commit') {
        for (const p of parseCommit(obj.data).parents) if (included.has(p)) walkQueue.push(p);
      } else if (obj.type === 'tag') {
        walkQueue.push(parseTag(obj.data).object);
      }
      continue;
    }
    send.set(oid, obj);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      walkQueue.push(c.tree);
      for (const p of c.parents) if (included.has(p)) walkQueue.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) walkQueue.push(e.oid);
    } else if (obj.type === 'tag') {
      walkQueue.push(parseTag(obj.data).object);
    }
  }
  if (send.size === 0) return { pack: null, shallow, unshallow };
  return { pack: writePack(send), shallow, unshallow };
}
async function handleUploadPack(req: IncomingMessage, res: ServerResponse, owner: string, name: string, bodyBuf: Buffer): Promise<void> {
  if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
  const r = findRepo(owner, name);
  if (!r) { errJson(res, 404, 'Not Found'); return; }
  const isV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
  const ct = 'application/x-git-upload-pack-result';
  let packets: Pkt[];
  try { packets = decodePktLines(bodyBuf); } catch { res.writeHead(400, { 'content-type': 'text/plain' }); res.end('bad pkt-line'); return; }
  const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  if (isV2) {
    const command = lines.find((l) => l.startsWith('command='))?.slice('command='.length).trim();
    const args = lines.slice(lines.findIndex((l) => l === 'delim' || l === 'flush') + 1).filter((l) => l !== 'flush');
    if (command === 'ls-refs') {
      const prefixes: string[] = [];
      let peel = false; let symrefs = false; let unborn = false;
      for (const a of args) {
        const t = a.trim();
        if (t.startsWith('ref-prefix ')) prefixes.push(t.slice('ref-prefix '.length));
        else if (t === 'peel') peel = true;
        else if (t === 'symrefs') symrefs = true;
        else if (t === 'unborn') unborn = true;
      }
      const out: string[] = [];
      const refs = refLines(r);
      const hasRefs = r.refs.size > 0;
      if (!hasRefs) {
        if (unborn) out.push(`unborn HEAD symref-target:refs/heads/${r.defaultBranch}\n`);
      } else {
        for (const ref of refs) {
          if (prefixes.length && !prefixes.some((p) => ref.name.startsWith(p))) continue;
          let line = `${ref.oid} ${ref.name}`;
          if (ref.name === 'HEAD' && symrefs && ref.symref) line += ` symref-target:${ref.symref}`;
          if (peel && ref.peeled) line += ` peeled:${ref.peeled}`;
          out.push(`${line}\n`);
        }
      }
      sendRaw(res, 200, pktLines([...out, 'flush']), ct);
      return;
    }
    if (command === 'fetch') {
      const wants: string[] = []; const haves: string[] = []; const shallowB: string[] = [];
      let depth: number | null = null;
      for (const a of args) {
        const t = a.trim();
        if (t.startsWith('want ')) wants.push(t.slice(5).trim());
        else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
        else if (t.startsWith('shallow ')) shallowB.push(t.slice(8).trim());
        else if (t.startsWith('deepen ')) depth = Number(t.slice(7).trim());
      }
      const { pack, shallow, unshallow } = fetchPack(wants, haves, depth, shallowB);
      const parts: Buffer[] = [];
      parts.push(pktLine('acknowledgments\n'));
      parts.push(pktLine('NAK\n'));
      parts.push(PKT_FLUSH);
      if (shallow.length || unshallow.length) {
        parts.push(pktLine('shallow-info\n'));
        for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
        for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
        parts.push(PKT_FLUSH);
      }
      if (pack) {
        parts.push(pktLine('packfile\n'));
        parts.push(sidebandPack(pack));
      }
      sendRaw(res, 200, Buffer.concat(parts), ct);
      return;
    }
    res.writeHead(400, { 'content-type': 'text/plain' }); res.end('unknown v2 command');
    return;
  }
  // v0 upload-pack
  const wants: string[] = []; const haves: string[] = []; const shallowB: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const p of packets) {
    if (p.kind === 'flush') { section += 1; continue; }
    if (p.kind !== 'data') continue;
    const t = p.payload.toString('utf8').trim();
    if (t.startsWith('want ')) wants.push(t.slice(5).split(' ')[0]!);
    else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) shallowB.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) depth = Number(t.slice(7).trim());
    void section;
  }
  const { pack, shallow, unshallow } = fetchPack(wants, haves, depth, shallowB);
  const parts: Buffer[] = [];
  parts.push(pktLine('NAK\n'));
  for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  if (pack) parts.push(sidebandPack(pack));
  else parts.push(PKT_FLUSH);
  sendRaw(res, 200, Buffer.concat(parts), ct);
}
async function handleReceivePack(req: IncomingMessage, res: ServerResponse, owner: string, name: string, bodyBuf: Buffer): Promise<void> {
  if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
  const r = findRepo(owner, name);
  if (!r) { errJson(res, 404, 'Not Found'); return; }
  const ct = 'application/x-git-receive-pack-result';
  const { packets, tail } = splitPktPrefix(bodyBuf);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  for (const p of packets) {
    if (p.kind !== 'data') continue;
    let text = p.payload.toString('utf8');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const parts = text.trim().split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts[2]! });
  }
  // Store the pack's objects (if any).
  let unpackOk = true;
  if (tail.length > 0) {
    try {
      const objs = readPack(tail);
      for (const [oid, obj] of objs) if (!objects.has(oid)) objects.set(oid, obj);
    } catch { unpackOk = false; }
  }
  const reportLines: string[] = [];
  reportLines.push(unpackOk ? 'unpack ok\n' : 'unpack error\n');
  for (const cmd of commands) {
    const current = r.refs.get(cmd.ref) ?? ZERO_OID;
    if (!unpackOk) { reportLines.push(`ng ${cmd.ref} unpack failed\n`); continue; }
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
      r.refs.delete(cmd.ref);
      if (cmd.ref.startsWith('refs/heads/')) r.files.delete(cmd.ref.slice('refs/heads/'.length));
      reportLines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    if (!objects.has(cmd.newOid)) { reportLines.push(`ng ${cmd.ref} object not found\n`); continue; }
    if (current === ZERO_OID) {
      // create
      if (cmd.oldOid !== ZERO_OID) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
      r.refs.set(cmd.ref, cmd.newOid);
      if (cmd.ref.startsWith('refs/heads/')) refreshBranchFiles(r, cmd.ref.slice('refs/heads/'.length));
      reportLines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    if (cmd.oldOid !== current) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    if (!isAncestor(current, cmd.newOid)) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    r.refs.set(cmd.ref, cmd.newOid);
    if (cmd.ref.startsWith('refs/heads/')) refreshBranchFiles(r, cmd.ref.slice('refs/heads/'.length));
    reportLines.push(`ok ${cmd.ref}\n`);
  }
  // Report inside sideband band 1, itself pkt-lined, then a flush.
  const inner = pktLines(reportLines);
  const outer = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), inner])), PKT_FLUSH]);
  sendRaw(res, 200, outer, ct);
}

// --------------------------------------------------------------------------- server

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async (): Promise<void> => {
      try {
        const method = req.method ?? 'GET';
        let pathname = '/';
        let query = new URLSearchParams();
        try { const u = new URL(req.url ?? '/', 'http://entry'); pathname = u.pathname; query = u.searchParams; } catch { /* keep defaults */ }
        if (method === 'GET' && pathname === '/healthz') { sendJson(res, 200, { ok: true }); return; }
        const bodyBuf = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
        if (pathname === '/api/graphql' && method === 'POST') { await handleGraphQL(req, res, bodyBuf); return; }
        if (pathname === '/mcp' && method === 'POST') { await handleMcp(req, res, bodyBuf); return; }
        if (pathname.startsWith('/api/v3')) { await handleRest(req, res, pathname, query, bodyBuf); return; }
        // git smart HTTP: /{owner}/{repo}.git/...
        const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(pathname);
        if (gitMatch) {
          const owner = decodePath(gitMatch[1]!);
          const name = decodePath(gitMatch[2]!);
          const sub = gitMatch[3] ?? '';
          if (method === 'GET' && sub === '/info/refs') {
            const service = query.get('service') ?? '';
            if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { errJson(res, 400, 'Unknown service'); return; }
            handleInfoRefs(req, res, owner, name, service);
            return;
          }
          if (method === 'POST' && sub === '/git-upload-pack') { await handleUploadPack(req, res, owner, name, bodyBuf); return; }
          if (method === 'POST' && sub === '/git-receive-pack') { await handleReceivePack(req, res, owner, name, bodyBuf); return; }
          errJson(res, 404, 'Not Found');
          return;
        }
        errJson(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) {
          try { errJson(res, 500, err instanceof Error ? err.message : 'Internal error'); } catch { /* socket gone */ }
        } else { try { res.end(); } catch { /* ignore */ } }
      }
    })();
  });
}
