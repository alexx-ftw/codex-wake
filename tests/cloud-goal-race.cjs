const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const WebSocket = require('ws');
const home = mkdtempSync(join(tmpdir(), 'wake-goal-race-'));
const socket = join(home, 'controller.sock');
const env = { ...process.env, HOME: home, CODEX_HOME: home, XDG_STATE_HOME: home };
for (const key of Object.keys(env)) if (/(^|_)(api.?key|token|secret|auth|credential)/i.test(key)) delete env[key];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let child, ws, serial = 0;
const pending = new Map();
function request(method, params) {
  const id = ++serial;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(Error('timeout ' + method)); }, 15000);
    pending.set(id, msg => { clearTimeout(timer); msg.error ? reject(Error(msg.error.message)) : resolve(msg.result); });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
(async () => {
  try {
    child = spawn(process.env.WAKE_TEST_CODEX, ['app-server', '--listen', 'unix://' + socket], { env, cwd: home, stdio: 'ignore' });
    for (let i = 0; i < 100 && !existsSync(socket); i++) await sleep(100);
    if (!existsSync(socket)) throw Error('isolated socket unavailable');
    ws = new WebSocket('ws+unix://' + socket + ':/');
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    ws.on('message', raw => { const msg = JSON.parse(raw); const cb = pending.get(msg.id); if (cb) { pending.delete(msg.id); cb(msg); } });
    await request('initialize', { clientInfo: { name: 'wake-goal-race', version: '1' }, capabilities: { experimentalApi: true } });
    ws.send(JSON.stringify({ method: 'initialized', params: {} }));
    const started = await request('thread/start', { cwd: home, model: 'gpt-6.1-terra', config: { model_reasoning_effort: 'medium' }, ephemeral: false });
    const threadId = started.thread.id;
    await request('thread/goal/set', { threadId, origin: 'automatic', objective: 'Isolated goal state race test', status: 'blocked' });
    const first = (await request('thread/goal/get', { threadId })).goal;
    if (first.status !== 'blocked') throw Error('blocked baseline not confirmed');
    await request('thread/goal/set', { threadId, origin: 'user', status: 'paused' });
    let updateError = null;
    try { await request('thread/goal/set', { threadId, origin: 'automatic', status: 'active' }); }
    catch (error) { updateError = error.message.slice(0, 150); }
    const last = (await request('thread/goal/get', { threadId })).goal;
    console.log(JSON.stringify({ isolated: true, original_status: first.status, intervening_user_status: 'paused', resulting_status: last.status, automatic_overrode_pause: last.status === 'active', automatic_error: updateError, credentials: false }));
  } catch (error) { console.log(JSON.stringify({ isolated: true, error: error.message })); process.exitCode = 1; }
  finally {
    if (ws) ws.terminate();
    if (child && child.exitCode === null) { const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM'); await exited; }
    rmSync(home, { recursive: true, force: true });
  }
})();
