const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');
const root = process.env.WAKE_PROOF_ROOT;
if (!root || !/^\/tmp\/wake-interrupt-cli\.[A-Za-z0-9]+$/.test(root)) throw Error('Expected isolated proof directory');
const env = { PATH: process.env.PATH, HOME: root, CODEX_HOME: root + '/codex', XDG_STATE_HOME: root, OCX_SHIM_BYPASS: '1', LANG: 'C.UTF-8' };
const hook = name => ({ hooks: [{ type: 'command', command: `sh -c 'cat > "${root}/${name}.json"; printf "{}\\n"'` }] });
fs.mkdirSync(root + '/codex-wake', { mode: 0o700 });
fs.writeFileSync(root + '/codex-wake/service.lock', '', { mode: 0o600 });
const interruptHook = { hooks: [{ type: 'command', command: `sh ${JSON.stringify(path.resolve(__dirname, '../../scripts/interrupt.sh'))}`, timeout: 3 }] };
fs.writeFileSync(root + '/codex/hooks.json', JSON.stringify({ hooks: { SessionStart: [hook('start')], Interrupt: [interruptHook], Stop: [hook('stop')] } }));
let child;
const server = http.createServer((req, res) => {
  if (!req.url?.includes('/responses')) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': 'text/event-stream' });
  res.write('event: response.created\ndata: ' + JSON.stringify({ type: 'response.created', response: { id: 'fixture', object: 'response', status: 'in_progress', output: [] } }) + '\n\n');
  setTimeout(() => child.kill('SIGINT'), 200);
});
server.listen(0, '127.0.0.1', () => {
  fs.writeFileSync(root + '/codex/config.toml', `model = "fixture-model"\nmodel_provider = "fixture"\n[model_providers.fixture]\nname = "fixture"\nbase_url = "http://127.0.0.1:${server.address().port}/v1"\nwire_api = "responses"\nrequires_openai_auth = false\n[features]\nhooks = true\n`);
  child = spawn(process.env.WAKE_PROOF_CODEX || 'codex', ['--dangerously-bypass-hook-trust', 'exec', '--skip-git-repo-check', 'Synthetic interruption fixture.'], { cwd: root + '/work', env, stdio: ['ignore', 'ignore', 'ignore'] });
  const timer = setTimeout(() => child.kill('SIGTERM'), 8000);
  child.on('close', (code, signal) => {
    clearTimeout(timer);
    const read = name => { const file = root + '/' + name + '.json'; return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null; };
    const start = read('start'), stop = read('stop');
    const records = fs.readdirSync(root + '/codex-wake').filter(name => name.startsWith('.interrupt.') && name.endsWith('.json'));
    const interrupt = records.length === 1 ? JSON.parse(fs.readFileSync(root + '/codex-wake/' + records[0], 'utf8')) : null;
    const lines = interrupt?.transcript_path && fs.existsSync(interrupt.transcript_path) ? fs.readFileSync(interrupt.transcript_path, 'utf8').split('\n').filter(Boolean).map(JSON.parse) : [];
    const aborts = lines.filter(x => x.type === 'event_msg' && x.payload?.type === 'turn_aborted' && x.payload?.turn_id === interrupt?.turn_id && x.payload?.reason === 'interrupted');
    const receipt = { exit_code: code, exit_signal: signal, start_seen: !!start, interrupt_seen: !!interrupt, stop_seen: !!stop, same_session: !!interrupt && interrupt.session_id === start?.session_id, interrupt_turn_id: interrupt?.turn_id || null, matching_abort_records: aborts.length };
    fs.writeFileSync(root + '/result.json', JSON.stringify(receipt, null, 2));
    console.log(JSON.stringify(receipt));
    if (!start || !interrupt || !receipt.same_session || !receipt.interrupt_turn_id || aborts.length !== 1) process.exitCode = 1;
    server.closeAllConnections(); server.close();
  });
});
