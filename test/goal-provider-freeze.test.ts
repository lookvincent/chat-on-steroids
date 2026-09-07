/**
 * Provider freeze: one Goal request uses a single consistent
 * one provider configuration even if settings change mid-flight.
 *
 * A provider switch landing between run()'s key read and the fetch used to mix
 * key-A with endpoint-B, because the endpoint and reasoning were re-read live at
 * request time. The draft now freezes endpoint/model/reasoning before reading that
 * provider kind's matching key.
 * This test pins the interleaving deterministically: the transcript read stays
 * pending while the switch is fully applied, so only a live re-read can observe B.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('electron', () => ({
  app: { getPath: () => '', getVersion: () => '0.0.0' },
  safeStorage: {
    isAsyncEncryptionAvailable: async () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptStringAsync: async (value: string) => Buffer.from(value, 'utf8'),
    decryptStringAsync: async (buffer: Buffer) => ({ result: buffer.toString('utf8'), shouldReEncrypt: false })
  }
}));

let releaseTranscript: ((events: unknown[]) => void) | null = null;
vi.mock('../src/main/session/store.js', () => ({
  getSession: async () => null,
  readEvents: async () => [],
  readHandoff: async () => null,
  readRecentEvents: () =>
    new Promise((resolve) => {
      releaseTranscript = resolve as (events: unknown[]) => void;
    })
}));

const { defaultConfig, initConfigPath, saveConfig } = await import('../src/main/config.js');
const { initSecretsPath, setSecret } = await import('../src/main/secrets.js');
const goal = await import('../src/main/goal.js');
const { makeTempDir, removeTempDir } = await import('./helpers.js');

const realFetch = globalThis.fetch;
let dir: string;

function decision(action: 'stop' | 'continue', reply = ''): Response {
  return Response.json({
    choices: [{ message: { content: JSON.stringify({ action, reply }) } }]
  });
}

async function settled(conversationId: string): Promise<NonNullable<ReturnType<typeof goal.goalViewFor>>> {
  for (let attempt = 0; attempt < 400; attempt++) {
    const view = goal.goalViewFor(conversationId);
    if (view && view.stage !== 'sending' && view.stage !== 'answering') return view;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('the draft never settled');
}

beforeAll(async () => {
  dir = await makeTempDir('clf-goal-freeze-');
  initConfigPath(dir);
  initSecretsPath(dir);
});

afterAll(async () => {
  await removeTempDir(dir);
  globalThis.fetch = realFetch;
});

beforeEach(async () => {
  goal.resetGoalStateForTests();
  releaseTranscript = null;
  await saveConfig({
    ...defaultConfig(),
    goal: {
      ...defaultConfig().goal,
      enabled: true,
      backend: 'api',
      loopBackend: 'api',
      model: 'llama3.1',
      reasoning: 'high',
      provider: { kind: 'custom', baseUrl: 'http://127.0.0.1:9501/v1' }
    }
  });
  await setSecret('customProviderApiKey', 'sk-custom-A');
  await setSecret('openRouterApiKey', '');
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('a mid-flight provider switch', () => {
  it('keeps the frozen endpoint, model and reasoning with its matching provider key', async () => {
    let sent: any = null;
    globalThis.fetch = (async (url: string, init: RequestInit) => {
      sent = { url, headers: init.headers, body: JSON.parse(String(init.body)), redirect: init.redirect };
      return decision('continue', 'check the tokenizer first');
    }) as never;

    // run() starts synchronously through beginGoalDraft and suspends inside the
    // transcript read below: endpoint A, key A and reasoning high are already frozen.
    goal.startGoalDraft({ sessionId: 's-freeze', conversationId: 'c-freeze', turnId: 'g-1' });
    for (let attempt = 0; attempt < 200 && releaseTranscript === null; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(releaseTranscript).not.toBeNull();

    // Fully applied while the request above is suspended: URL, key and reasoning all
    // change. A live re-read at request time would mix key-A with endpoint-B.
    await saveConfig({
      ...defaultConfig(),
      goal: {
        ...defaultConfig().goal,
        enabled: true,
        backend: 'api',
        loopBackend: 'api',
        model: 'qwen3:8b',
        reasoning: 'low',
        provider: { kind: 'custom', baseUrl: 'http://127.0.0.1:9502/v1' }
      }
    });
    await setSecret('customProviderApiKey', 'sk-custom-B');

    releaseTranscript!([
      { kind: 'user_message', message: { text: 'build the parser', truncated: false, chars: 16 } }
    ]);
    const view = await settled('c-freeze');

    expect(view.stage).toBe('ready');
    expect(sent.url).toBe('http://127.0.0.1:9501/v1/chat/completions');
    expect((sent.headers as Record<string, string>).authorization).toBe('Bearer sk-custom-A');
    expect(sent.body.model).toBe('llama3.1');
    expect(sent.body.reasoning_effort).toBe('high');
    expect(sent.body).not.toHaveProperty('reasoning');
    expect(sent.redirect).toBe('error');
  });
});
