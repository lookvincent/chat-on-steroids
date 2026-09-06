/**
 * Trusted gateway from a ChatGPT-injected file reference to a readable byte stream.
 *
 * Ported from devspace `src/incoming-artifacts.ts`: the model never supplies bytes or
 * URLs directly. ChatGPT injects `{download_url, file_id, ...}` because the tool schema
 * carries `_meta: {"openai/fileParams": ["file"]}`; this module validates that value and
 * fetches it. Anything the model invents fails here, before any disk is touched.
 */

import { basename, isAbsolute } from 'node:path';
import { Readable } from 'node:stream';
import type { ReadableStream as NodeReadableStream } from 'node:stream/web';

const OPENAI_FILE_HOSTS = new Set(['files.oaiusercontent.com']);
// ChatGPT-generated files are served from regional OpenAI-managed Azure storage
// accounts. Accept that account family only, never arbitrary Azure Blob hosts.
const OPENAI_REGIONAL_BLOB_HOST_PATTERN = /^oaisdmntpr[a-z0-9]+\.blob\.core\.windows\.net$/u;
const OPENAI_FILENAME_SAFE_FILE_ID_PATTERN = /^file[-_][A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const OPENAI_FILE_ID_MAX_LENGTH = 512;
const OPENAI_FILE_ID_CONTROL_PATTERN = /[\u0000-\u001F\u007F]/u;
const OPENAI_FILE_KEYS = new Set([
  'download_url',
  'file_id',
  'mime_type',
  'file_name',
  'name',
  'size'
]);
const OPENAI_FILE_REDIRECT_LIMIT = 3;
const OPENAI_FILE_DOWNLOAD_TIMEOUT_MS = 30_000;

export class ArtifactFetchError extends Error {}

export interface ArtifactSource {
  name: string;
  mimeType?: string;
  size?: number;
  stream: Readable;
}

export interface OpenAIFileReference {
  download_url: string;
  file_id: string;
  mime_type?: string;
  file_name?: string;
  size?: number;
}

export interface OpenAIFileAdapterOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Shape-only summary for logs: type/length/URL-kind, never the URL or id itself.
 * Mirrors devspace describeIncomingArtifactValue for the fields this tool accepts.
 */
export function describeArtifactFileValue(value: unknown): unknown {
  if (value === null || value === undefined) return { type: value === null ? 'null' : 'undefined' };
  if (typeof value !== 'object' || Array.isArray(value)) {
    return { type: Array.isArray(value) ? 'array' : typeof value };
  }
  const entries: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort().slice(0, 20)) {
    const entry = (value as Record<string, unknown>)[key];
    entries[key] =
      typeof entry === 'string'
        ? { type: 'string', kind: classifyValueString(entry), length: entry.length }
        : { type: typeof entry };
  }
  return { type: 'object', entries };
}

/** Hostname only, for logs. Returns null when the reference has no usable URL. */
export function artifactFileHostname(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return null;
  const raw = (value as Record<string, unknown>)['download_url'];
  if (typeof raw !== 'string') return null;
  try {
    return new URL(raw).hostname;
  } catch {
    return null;
  }
}

export function isOpenAIFileReferenceCandidate(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return (
    keys.length >= 2 &&
    keys.every((key) => OPENAI_FILE_KEYS.has(key)) &&
    Object.hasOwn(value, 'download_url') &&
    Object.hasOwn(value, 'file_id')
  );
}

export function normalizeOpenAIFileReference(value: unknown): OpenAIFileReference {
  if (!isOpenAIFileReferenceCandidate(value)) {
    throw new ArtifactFetchError('ChatGPT file reference is malformed.');
  }
  const downloadUrl = value['download_url'];
  const fileId = value['file_id'];
  if (typeof downloadUrl !== 'string' || typeof fileId !== 'string' || !isValidOpenAIFileId(fileId)) {
    throw new ArtifactFetchError('ChatGPT file reference is malformed.');
  }
  const mimeType = nullableString(value['mime_type']);
  const fileName = nullableString(value['file_name']);
  const nameAlias = nullableString(value['name']);
  if (mimeType === null || fileName === null || nameAlias === null) {
    throw new ArtifactFetchError('ChatGPT file reference is malformed.');
  }
  const normalizedFileName = normalizeSuppliedFileName(fileName);
  const normalizedNameAlias = normalizeSuppliedFileName(nameAlias);
  if (normalizedFileName && normalizedNameAlias && normalizedFileName !== normalizedNameAlias) {
    throw new ArtifactFetchError('ChatGPT file reference contained conflicting filenames.');
  }
  let size: number | undefined;
  const rawSize = value['size'];
  if (rawSize !== undefined && rawSize !== null) {
    if (typeof rawSize !== 'number' || !Number.isSafeInteger(rawSize) || rawSize < 0) {
      throw new ArtifactFetchError('ChatGPT file reference is malformed.');
    }
    size = rawSize;
  }
  return {
    download_url: downloadUrl,
    file_id: fileId,
    mime_type: mimeType,
    file_name: normalizedFileName ?? normalizedNameAlias,
    size
  };
}

/** Fetch the trusted file URL and return its stream. Every redirect is re-validated. */
export async function openArtifactFile(
  value: unknown,
  options: OpenAIFileAdapterOptions = {}
): Promise<ArtifactSource> {
  const fetchFile = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? OPENAI_FILE_DOWNLOAD_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new ArtifactFetchError('Artifact download timeout must be a positive integer.');
  }
  const reference = normalizeOpenAIFileReference(value);

  let downloadUrl = validateOpenAIFileUrl(reference.download_url);
  let response: Response | undefined;
  for (let redirect = 0; redirect <= OPENAI_FILE_REDIRECT_LIMIT; redirect += 1) {
    try {
      response = await fetchFile(downloadUrl, {
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch {
      throw new ArtifactFetchError('ChatGPT file could not be downloaded.');
    }
    if (!isRedirectStatus(response.status)) break;
    const location = response.headers.get('location');
    await response.body?.cancel().catch(() => undefined);
    if (!location || redirect === OPENAI_FILE_REDIRECT_LIMIT) {
      throw new ArtifactFetchError('ChatGPT file download returned an invalid redirect.');
    }
    downloadUrl = validateOpenAIFileUrl(new URL(location, downloadUrl).toString());
  }

  if (!response?.ok || !response.body) {
    await response?.body?.cancel().catch(() => undefined);
    throw new ArtifactFetchError('ChatGPT file download did not return file content.');
  }
  const responseSize = responseContentLength(response);
  if (reference.size !== undefined && responseSize !== undefined && reference.size !== responseSize) {
    await response.body.cancel().catch(() => undefined);
    throw new ArtifactFetchError('ChatGPT file metadata did not match the downloaded content.');
  }
  const mimeType = reference.mime_type ?? responseMimeType(response);
  const source: ArtifactSource = {
    name: normalizeOpenAIFileName(reference.file_name, reference.file_id, mimeType),
    mimeType,
    size: responseSize ?? reference.size,
    stream: Readable.fromWeb(response.body as unknown as NodeReadableStream)
  };
  validateArtifactSource(source);
  return source;
}

function validateArtifactSource(source: ArtifactSource): void {
  if (typeof source.name !== 'string' || source.name.length === 0) {
    throw new ArtifactFetchError('ChatGPT file adapter must provide a filename.');
  }
  if (source.size !== undefined && (!Number.isSafeInteger(source.size) || source.size < 0)) {
    throw new ArtifactFetchError('ChatGPT file adapter returned an invalid byte size.');
  }
  const stream = source.stream as Partial<Readable> | undefined;
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
    source.stream?.destroy?.();
    throw new ArtifactFetchError('ChatGPT file adapter must provide an async-readable stream.');
  }
}

function nullableString(value: unknown): string | undefined | null {
  if (value === undefined || value === null) return undefined;
  return typeof value === 'string' ? value : null;
}

function normalizeOpenAIFileName(
  suppliedName: string | undefined,
  fileId: string,
  mimeType: string | undefined
): string {
  if (suppliedName) return suppliedName;
  const safeBaseName = OPENAI_FILENAME_SAFE_FILE_ID_PATTERN.test(fileId) ? fileId : 'chatgpt-file';
  return `${safeBaseName}${extensionForMimeType(mimeType) ?? '.bin'}`;
}

function isValidOpenAIFileId(value: string): boolean {
  return (
    value.length > 0 && value.length <= OPENAI_FILE_ID_MAX_LENGTH && !OPENAI_FILE_ID_CONTROL_PATTERN.test(value)
  );
}

function normalizeSuppliedFileName(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const candidate = basename(value.replaceAll('\\', '/')).trim();
  if (!candidate || candidate === '.' || candidate === '..' || candidate.startsWith('.')) return undefined;
  return candidate;
}

function extensionForMimeType(mimeType: string | undefined): string | undefined {
  switch (mimeType?.toLowerCase()) {
    case 'image/png':
      return '.png';
    case 'image/jpeg':
      return '.jpg';
    case 'image/webp':
      return '.webp';
    case 'image/gif':
      return '.gif';
    case 'application/pdf':
      return '.pdf';
    case 'text/plain':
      return '.txt';
    case 'application/zip':
      return '.zip';
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
      return '.docx';
    default:
      return undefined;
  }
}

export function validateOpenAIFileUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ArtifactFetchError('ChatGPT file download URL is invalid.');
  }
  if (
    url.protocol !== 'https:' ||
    !isTrustedOpenAIFileHost(url.hostname) ||
    (url.port !== '' && url.port !== '443') ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== ''
  ) {
    throw new ArtifactFetchError('ChatGPT file download URL is outside the trusted file host.');
  }
  return url.toString();
}

function isTrustedOpenAIFileHost(hostname: string): boolean {
  return OPENAI_FILE_HOSTS.has(hostname) || OPENAI_REGIONAL_BLOB_HOST_PATTERN.test(hostname);
}

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function responseMimeType(response: Response): string | undefined {
  const value = response.headers.get('content-type')?.split(';', 1)[0]?.trim();
  return value || undefined;
}

function responseContentLength(response: Response): number | undefined {
  const value = response.headers.get('content-length');
  if (!value || !/^\d+$/u.test(value)) return undefined;
  const size = Number(value);
  return Number.isSafeInteger(size) ? size : undefined;
}

function classifyValueString(value: string): 'absolute-path' | 'url' | 'data-url' | 'text' {
  if (value.startsWith('data:')) return 'data-url';
  if (isAbsolute(value)) return 'absolute-path';
  try {
    const parsed = new URL(value);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return 'url';
  } catch {
    // Non-URL strings are summarized only by type and length.
  }
  return 'text';
}
