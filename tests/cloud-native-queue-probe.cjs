const { spawn, spawnSync } = require('node:child_process');
const { mkdtempSync, rmSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const WebSocket = require('ws');

const home = mkdtempSync(join(tmpdir(), 'wake-native-e2e-'));
const socket = join(home, 'controller.sock');
const db = join(home, 'wake.sqlite3');
const binary = process.env.WAKE_TEST_BINARY;
const codex = process.env.WAKE_TEST_CODEX;
const env = { ...process.env, HOME: home, CODEX_HOME: home, XDG_STATE_HOME: home,
  CODEX_WAKE_RPC_SOCKET: socket, CODEX_WAKE_DB: db, CODEX_WAKE_CODEX: codex,
  CODEX_WAKE_ENABLE_WEBHOOKS: '0' };
for (const key of Object.keys(env)) if (/(^|_)(api.?key|token|secret|auth|credential)/i.test(key)) delete env[key];
for (const key of ['CODEX_WAKE_PLUGIN_ROOT', 'CODEX_WAKE_PLUGIN_BASE']) delete env[key];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let child, receiver, ws, serial = 0;
const pending = new Map();
function request(method, params) {
  const id = ++serial;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(Error(`timeout: ${method}`)); }, 15000);
    pending.set(id, msg => { clearTimeout(timer); msg.error ? reject(Error(msg.error.message)) : resolve(msg.result); });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
function cli(args, input) {
  const run = spawnSync(binary, ['--db', db, '--codex', codex, ...args], { env, input, encoding: 'utf8', timeout: 45000 });
  if (run.status !== 0) throw Error(`wake ${args[0]} failed: ${(run.stderr || '').slice(0, 500)}`);
  return JSON.parse(run.stdout);
}
(async () => {
  try {
    child = spawn(codex, ['app-server', '--listen', `unix://${socket}`], { env, cwd: home, stdio: 'ignore' });
    for (let i = 0; i < 100 && !existsSync(socket); i++) await sleep(100);
    if (!existsSync(socket)) throw Error('isolated server socket missing');
    ws = new WebSocket(`ws+unix://${socket}:/`);
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    ws.on('message', raw => { const msg = JSON.parse(raw); const cb = pending.get(msg.id); if (cb) { pending.delete(msg.id); cb(msg); } });
    await request('initialize', { clientInfo: { name: 'wake-native-e2e', version: '1' }, capabilities: { experimentalApi: true } });
    ws.send(JSON.stringify({ method: 'initialized', params: {} }));
    const started = await request('thread/start', { cwd: home, model: 'gpt-6.1-terra', config: { model_reasoning_effort: 'medium' }, ephemeral: false });
    const thread = started.thread.id;
    const sha = 'a'.repeat(40);
    cli(['register', '--repo', 'isolated/example', '--run', '123456', '--attempt', '1', '--thread', thread, '--sha', sha]);
    const payload = JSON.stringify({ action: 'completed', repository: { full_name: 'isolated/example' }, workflow_run: { id: 123456, run_attempt: 1, head_sha: sha, status: 'completed', conclusion: 'success' } });
    cli(['handle'], payload);
    const query = spawnSync('sqlite3', ['-readonly', db, "SELECT e.client_user_message_id,w.state,coalesce(w.reason,'') FROM delivery_evidence e JOIN waits w ON w.thread=e.target_thread"], { encoding: 'utf8' });
    if (query.status !== 0) throw Error('evidence query failed');
    const [clientId, state, reason] = query.stdout.trim().split('|');
    if (!clientId || state !== 'queued' || !['native_queue_accepted', 'native_queue_resume_warning'].includes(reason)) throw Error(`unexpected queue state: ${state}/${reason}`);
    let matches = 0;
    for (let i = 0; i < 60 && !matches; i++) {
      try {
        const page = await request('thread/turns/list', { threadId: thread, limit: 10, sortDirection: 'desc', itemsView: 'full' });
        matches = (page.data || []).flatMap(turn => turn.items || []).filter(item => item.type === 'userMessage' && item.clientId === clientId).length;
      } catch {}
      if (!matches) await sleep(500);
    }
    if (matches !== 1) throw Error(`expected one persisted matching message, got ${matches}`);
    cli(['handle'], payload);
    const stateAfter = spawnSync('sqlite3', ['-readonly', db, 'SELECT count(*) FROM delivery_evidence'], { encoding: 'utf8' }).stdout.trim();
    const pageAfter = await request('thread/turns/list', { threadId: thread, limit: 10, sortDirection: 'desc', itemsView: 'full' });
    const after = (pageAfter.data || []).flatMap(turn => turn.items || []).filter(item => item.type === 'userMessage' && item.clientId === clientId).length;
    if (stateAfter !== '1' || after !== 1) throw Error('replayed event created unexpected identity or message');
    const result = { isolated: true, queued: state, reason, persisted_messages: matches, repeated_event_messages: after, evidence_rows: Number(stateAfter), no_credentials: true };
    if (process.argv.includes('--duplicate')) {
      let page = await request('thread/turns/list', { threadId: thread, limit: 10, sortDirection: 'desc', itemsView: 'full' });
      const active = (page.data || []).find(turn => turn.status === 'inProgress');
      if (active) await request('turn/interrupt', { threadId: thread, turnId: active.id });
      let idle = false;
      for (let i = 0; i < 60 && !idle; i++) {
        const read = await request('thread/read', { threadId: thread, includeTurns: false });
        idle = read.thread.status.type === 'idle';
        if (!idle) await sleep(500);
      }
      if (!idle) throw Error('isolated chat did not become idle');
      receiver = spawn(binary, ['--db', db, '--codex', codex, 'receiver'], { env, cwd: home, stdio: 'ignore' });
      await request('turn/start', { threadId: thread, clientUserMessageId: clientId, input: [{ type: 'text', text: 'Isolated duplicate receipt test; do not execute.', text_elements: [] }] });
      let observed = '', warning = '';
      for (let i = 0; i < 90 && !(observed === 'duplicate_confirmed' && warning === 'accepted_unconfirmed'); i++) {
        await sleep(500);
        [observed, warning] = spawnSync('sqlite3', ['-readonly', db, "SELECT coverage_state||'|'||warning_state FROM delivery_evidence"], { encoding: 'utf8' }).stdout.trim().split('|');
      }
      page = await request('thread/turns/list', { threadId: thread, limit: 10, sortDirection: 'desc', itemsView: 'full' });
      result.intentional_duplicate_messages = (page.data || []).flatMap(turn => turn.items || []).filter(item => item.type === 'userMessage' && item.clientId === clientId).length;
      result.duplicate_detection = observed;
      result.warning_state = warning;
      if (result.intentional_duplicate_messages !== 2 || observed !== 'duplicate_confirmed' || result.warning_state !== 'accepted_unconfirmed') throw Error(`duplicate not confirmed: ${JSON.stringify(result)}`);
    }
    console.log(JSON.stringify(result));
  } catch (error) { console.log(JSON.stringify({ isolated: true, error: error.message })); process.exitCode = 1; }
  finally {
    if (receiver && receiver.exitCode === null) { const exited = new Promise(resolve => receiver.once('exit', resolve)); receiver.kill('SIGTERM'); await exited; }
    if (ws) ws.terminate();
    if (child && child.exitCode === null) { const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exited; }
    rmSync(home, { recursive: true, force: true });
  }
})();
