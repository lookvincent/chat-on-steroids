/**
 * Secure local target for one `download_artifact` call.
 *
 * Simplified port of devspace `src/artifact-secure-filesystem-{common,linux}.ts`
 * without koffi: containment is owned by `sandbox.resolvePath` (checked by the caller
 * before this module is entered), and this module owns the publication semantics —
 * exclusive partial beside the destination, fsync, fstat-vs-lstat verification and an
 * atomic link publish that never overwrites. The check-to-use window is narrowed by
 * re-verifying the parent with lstat immediately before and after the publish; a fully
 * fd-pinned backend (openat/linkat) remains a possible phase two with this same interface.
 */

import { randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { rawPromises as fs } from '../rawfs.js';

export const ARTIFACT_PARTIAL_PREFIX = '.steroids-download-';
export const ARTIFACT_PARTIAL_SUFFIX = '.partial';

export class ArtifactTargetError extends Error {}

export interface ArtifactTargetOptions {
  /** Canonical real path of the already-validated parent directory. */
  parentReal: string;
  /** Canonical real path of the approved root, for the pre-write containment re-check. */
  rootReal: string;
  /** Final file name (one validated segment, never a path). */
  name: string;
  /** Per-file byte ceiling. */
  maxFileBytes: number;
}

export interface ArtifactTarget {
  writeAll(buffer: Buffer, position: number): Promise<void>;
  syncAndVerify(expectedSize: number): Promise<void>;
  publish(): Promise<void>;
  close(): Promise<void>;
  /** Bytes written so far (for the streaming limit check in the caller). */
  readonly size: number;
}

/**
 * Remove stale crash leftovers in one directory. Bounded and conservative: at most 32
 * entries are scanned, only this module's prefix+suffix, only regular files older than
 * 24h. Never throws.
 */
export async function cleanupStalePartials(dirReal: string): Promise<void> {
  let entries: string[];
  try {
    entries = await fs.readdir(dirReal);
  } catch {
    return;
  }
  let scanned = 0;
  for (const entry of entries) {
    if (scanned >= 32) return;
    scanned += 1;
    if (!entry.startsWith(ARTIFACT_PARTIAL_PREFIX) || !entry.endsWith(ARTIFACT_PARTIAL_SUFFIX)) continue;
    const candidate = path.join(dirReal, entry);
    try {
      const stat = await fs.lstat(candidate);
      if (!stat.isFile() || stat.isSymbolicLink()) continue;
      if (Date.now() - stat.mtimeMs < 24 * 60 * 60 * 1000) continue;
      await fs.unlink(candidate).catch(() => undefined);
    } catch {
      // A concurrent writer owns it now; leave it alone.
    }
  }
}

function isContainedPath(parentReal: string, childReal: string): boolean {
  const a = path.resolve(parentReal);
  const b = path.resolve(childReal);
  const norm = (s: string): string => (process.platform === 'win32' ? s.toLowerCase() : s);
  if (norm(a) === norm(b)) return true;
  const prefix = a.endsWith(path.sep) ? a : a + path.sep;
  return norm(b).startsWith(norm(prefix));
}

/** A name the sandbox already validated, re-checked defensively at the I/O boundary. */
export function assertSafeFileName(name: string): void {
  if (typeof name !== 'string' || name === '' || name === '.' || name === '..') {
    throw new ArtifactTargetError('Artifact destination is invalid.');
  }
  if (name.includes('/') || name.includes('\\') || name.includes('\0')) {
    throw new ArtifactTargetError('Artifact destination is invalid.');
  }
}

/**
 * Open the exclusive partial for one download. The parent must already exist and be a
 * real directory inside the approved root; missing intermediate folders are created by
 * the caller through validated sandbox paths, never here from raw strings.
 */
export async function openArtifactTarget(options: ArtifactTargetOptions): Promise<ArtifactTarget> {
  const { parentReal, rootReal, name, maxFileBytes } = options;
  assertSafeFileName(name);
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1) {
    throw new ArtifactTargetError('Artifact file-size limit must be a positive integer.');
  }

  let parentStat: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    parentStat = await fs.lstat(parentReal);
  } catch {
    throw new ArtifactTargetError('Artifact destination parent is not available.');
  }
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    throw new ArtifactTargetError('Artifact destination parent must be a real directory inside an approved folder.');
  }
  if (!isContainedPath(rootReal, parentReal)) {
    throw new ArtifactTargetError('Artifact destination escapes its approved folder.');
  }

  await cleanupStalePartials(parentReal).catch(() => undefined);

  const partialPath = path.join(parentReal, `${ARTIFACT_PARTIAL_PREFIX}${randomUUID()}${ARTIFACT_PARTIAL_SUFFIX}`);
  const candidatePath = path.join(parentReal, name);
  // Refuse to overwrite: the existence check and the exclusive link below are both
  // enforced, so a file created between them still fails at publish time.
  try {
    await fs.lstat(candidatePath);
    throw new ArtifactTargetError('Artifact destination already exists.');
  } catch (error) {
    if (error instanceof ArtifactTargetError) throw error;
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  let fileHandle: FileHandle | undefined;
  try {
    fileHandle = await fs.open(
      partialPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
      0o600
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new ArtifactTargetError('Artifact partial collision; retry the download.');
    }
    throw error;
  }

  let writtenBytes = 0;
  let writtenDev: number | undefined;
  let writtenIno: number | undefined;
  let verified = false;
  let published = false;
  let closed = false;

  async function close(): Promise<void> {
    if (closed) return;
    closed = true;
    await fileHandle?.close().catch(() => undefined);
    fileHandle = undefined;
    if (!published) await fs.unlink(partialPath).catch(() => undefined);
  }

  return {
    get size() {
      return writtenBytes;
    },
    async writeAll(buffer: Buffer, position: number): Promise<void> {
      if (!fileHandle || closed || verified) {
        throw new ArtifactTargetError('Artifact target is not writable.');
      }
      if (position !== writtenBytes) {
        throw new ArtifactTargetError('Artifact write is not sequential.');
      }
      if (writtenBytes + buffer.length > maxFileBytes) {
        throw new ArtifactTargetError('Artifact file exceeds the configured per-file limit.');
      }
      let offset = 0;
      while (offset < buffer.length) {
        const written = await fileHandle.write(buffer, offset, buffer.length - offset, position + offset);
        if (written.bytesWritten === 0) throw new ArtifactTargetError('Artifact write was interrupted.');
        offset += written.bytesWritten;
      }
      writtenBytes += buffer.length;
    },
    async syncAndVerify(expectedSize: number): Promise<void> {
      if (!fileHandle || closed) throw new ArtifactTargetError('Artifact target is not open.');
      if (writtenBytes !== expectedSize) {
        throw new ArtifactTargetError('Artifact size did not match the downloaded content.');
      }
      await fileHandle.sync();
      const fdStat = await fileHandle.stat();
      if (!fdStat.isFile() || fdStat.size !== expectedSize) {
        throw new ArtifactTargetError('Artifact partial is not a complete file.');
      }
      const pathStat = await fs.lstat(partialPath);
      if (pathStat.isSymbolicLink() || !pathStat.isFile() || pathStat.size !== expectedSize) {
        throw new ArtifactTargetError('Artifact partial changed before publication.');
      }
      // dev/ino bind the open description to the pathname: a swap between fsync and
      // publish changes one of them and fails the publish re-check below.
      writtenDev = fdStat.dev;
      writtenIno = fdStat.ino;
      verified = true;
    },
    async publish(): Promise<void> {
      if (!verified || writtenDev === undefined || writtenIno === undefined) {
        throw new Error('Artifact must be verified before publication.');
      }
      if (published) return;
      try {
        await fs.link(partialPath, candidatePath);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'EEXIST') throw new ArtifactTargetError('Artifact destination already exists.');
        if (code === 'EXDEV') {
          throw new ArtifactTargetError('Artifact partial and destination are on different filesystems.');
        }
        throw error;
      }
      const publishedStat = await fs.lstat(candidatePath);
      if (
        publishedStat.isSymbolicLink() ||
        !publishedStat.isFile() ||
        publishedStat.size !== writtenBytes ||
        publishedStat.dev !== writtenDev ||
        publishedStat.ino !== writtenIno
      ) {
        throw new ArtifactTargetError('Artifact could not be published at the requested destination.');
      }
      await fs.unlink(partialPath).catch(() => undefined);
      published = true;
    },
    close
  };
}
