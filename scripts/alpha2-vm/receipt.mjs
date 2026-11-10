import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export const artifacts = ['kernel', 'kernel.config', 'initramfs.cpio.zst', 'packages.tsv', 'inputs.sha256', 'source.json'];
export const digest = data => createHash('sha256').update(data).digest('hex');
export const sourcePaths = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'src', 'hooks.json.tmpl',
  'hooks/hooks.json', 'scripts/interrupt.sh', 'scripts/alpha2-vm'];
const read = (dir, name) => fs.readFileSync(path.join(dir, name));
const hash = (dir, name) => digest(read(dir, name));

export function evidence(dir, expectedSha) {
  assert.match(expectedSha, /^[a-f0-9]{40}$/);
  const source = JSON.parse(read(dir, 'source.json'));
  assert.equal(source.sha, expectedSha, 'wrong source SHA');
  assert.match(source.tree, /^[a-f0-9]{40}$/);
  const sums = read(dir, 'SHA256SUMS').toString().trim().split('\n');
  assert.equal(sums.length, artifacts.length);
  const hashes = {};
  for (const [i, name] of artifacts.entries()) {
    assert.equal(sums[i], `${hash(dir, name)}  ${name}`, `changed artifact: ${name}`);
    hashes[name] = hash(dir, name);
  }
  const consoleText = read(dir, 'console.log').toString().replaceAll('\r', '');
  const lines = consoleText.split('\n');
  const marker = prefix => {
    const matches = lines.filter(line => line.startsWith(prefix));
    assert.equal(matches.length, 1, `expected one ${prefix}`);
    return matches[0].slice(prefix.length);
  };
  const nonce = read(dir, 'nonce.txt').toString().trim();
  assert.match(nonce, /^[a-f0-9-]{36}$/);
  assert.equal(marker('VM_NONCE='), nonce, 'stale VM output');
  assert.equal(marker('VM_SOURCE_SHA='), expectedSha);
  assert.equal(marker('VM_EXIT='), '0');
  const result = JSON.parse(marker('VM_RESULT='));
  assert.equal(result.passed, true);
  assert.equal(result.phase, 'corrected hazards and integrated systemd transaction');
  assert.equal(result.systemd_pid1, true);
  assert.equal(result.production_migration_qualified, false);
  assert.equal(result.transition.passed, true);
  assert.equal(result.transition.production_migration_qualified, false);
  assert.equal(result.transition.uncertain_delivery_attempts_measured, true);
  assert.equal(result.transition.uncertain_delivery_attempts, 1);
  assert.equal(result.transition.uncertain_delivery_retries, 0);
  assert.equal(result.transition.uncertain_response_loss_exercised, true);
  assert.equal(result.transition.delivery_positive_controls, 2);
  assert(lines.findIndex(line => line.startsWith('VM_RESULT=')) < lines.findIndex(line => line.startsWith('VM_EXIT=')), 'result after exit');
  const accelerator = read(dir, 'accelerator.txt').toString().trim();
  assert(['kvm', 'tcg'].includes(accelerator));
  return {schema: 1, source, accelerator, artifacts: hashes, console_sha256: hash(dir, 'console.log'),
    qemu_stderr_sha256: hash(dir, 'qemu.stderr'), nonce, result};
}

function verifySource(source, expectedSha) {
  assert.match(expectedSha, /^[a-f0-9]{40}$/);
  assert.equal(source.sha, expectedSha, 'wrong source SHA');
  const git = args => execFileSync('git', args, {cwd: path.resolve(fileURLToPath(new URL('../..', import.meta.url)))});
  assert.equal(git(['rev-parse', `${expectedSha}^{tree}`]).toString().trim(), source.tree);
  const files = git(['ls-tree', '-rz', '--name-only', expectedSha, '--', ...sourcePaths]).toString().split('\0').filter(Boolean);
  assert.deepEqual(Object.keys(source.files).sort(), files.sort());
  for (const file of files) assert.equal(digest(git(['show', `${expectedSha}:${file}`])), source.files[file], `source mismatch: ${file}`);
}

export function verify(dir, expectedSha) {
  const bytes = read(dir, 'receipt.json');
  assert.equal(read(dir, 'receipt.sha256').toString(), `${digest(bytes)}  receipt.json\n`);
  const receipt = JSON.parse(bytes);
  assert.deepEqual(receipt, evidence(dir, expectedSha));
  verifySource(receipt.source, expectedSha);
  return receipt;
}

const guestFiles = ['legacy', 'new-wake', 'codex', 'vm-probe', 'fence.bpf.o', 'source.json'].map(name => '/guest/' + name);
const checks = Object.freeze({passed: true, systemd_pid1: true, uncertain_delivery_attempts: 1,
  uncertain_delivery_retries: 0, delivery_positive_controls: 2, production_migration_qualified: false});
function publicSource(source) {
  const field = (value, pattern) => { if (value == null) return null; assert.equal(typeof value, 'string'); assert.match(value, pattern); return value; };
  return {sha: source.sha, tree: source.tree, files: source.files,
    repository: field(source.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    run_id: field(source.run_id, /^\d+$/), run_attempt: field(source.run_attempt, /^\d+$/),
    runner_image: {os: field(source.runner_image?.os, /^[A-Za-z0-9_.-]+$/),
      version: field(source.runner_image?.version, /^[A-Za-z0-9_.-]+$/)}};
}
function versionsText(versions) {
  assert(Array.isArray(versions) && versions.length > 0);
  return versions.map(pair => {
    assert(Array.isArray(pair) && pair.length === 2);
    assert.match(pair[0], /^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$/);
    assert.match(pair[1], /^[0-9][A-Za-z0-9.+:~-]*$/);
    return pair.join('\t') + '\n';
  }).join('');
}
function inputsText(inputs) {
  assert.deepEqual(Object.keys(inputs), guestFiles);
  return guestFiles.map(name => { assert.match(inputs[name], /^[a-f0-9]{64}$/); return `${inputs[name]}  ${name}\n`; }).join('');
}

export function exportEvidence(dir, expectedSha, destination) {
  // Verify every raw file and Git binding before creating or selecting any export.
  const full = verify(dir, expectedSha);
  const versions = read(dir, 'packages.tsv').toString().trimEnd().split('\n').map(line => line.split('\t'));
  assert.equal(versionsText(versions), read(dir, 'packages.tsv').toString());
  const rows = read(dir, 'inputs.sha256').toString().trimEnd().split('\n');
  const guest_inputs = Object.fromEntries(guestFiles.map((name, i) => [name, rows[i]?.slice(0, 64)]));
  assert.equal(inputsText(guest_inputs), read(dir, 'inputs.sha256').toString());
  assert.equal(digest(versionsText(versions)), full.artifacts['packages.tsv']);
  assert.equal(digest(inputsText(guest_inputs)), full.artifacts['inputs.sha256']);
  const receipt = {schema: 2, kind: 'alpha2-vm-sanitized', verified_before_export: true,
    source: publicSource(full.source), accelerator: full.accelerator, artifacts: full.artifacts,
    console_sha256: full.console_sha256, qemu_stderr_sha256: full.qemu_stderr_sha256,
    checks, guest_inputs, versions};
  const bytes = JSON.stringify(receipt, null, 2) + '\n';
  fs.mkdirSync(destination);
  fs.writeFileSync(path.join(destination, 'receipt.json'), bytes, {flag: 'wx'});
  fs.writeFileSync(path.join(destination, 'SHA256SUMS'), `${digest(bytes)}  receipt.json\n`, {flag: 'wx'});
  return receipt;
}

export function verifyExport(dir, expectedSha) {
  assert.deepEqual(fs.readdirSync(dir).sort(), ['SHA256SUMS', 'receipt.json']);
  for (const name of ['SHA256SUMS', 'receipt.json']) assert(fs.lstatSync(path.join(dir, name)).isFile());
  assert.equal(read(dir, 'SHA256SUMS').toString(), `${hash(dir, 'receipt.json')}  receipt.json\n`);
  const receipt = JSON.parse(read(dir, 'receipt.json'));
  assert.deepEqual(Object.keys(receipt).sort(), ['schema', 'kind', 'verified_before_export', 'source', 'accelerator',
    'artifacts', 'console_sha256', 'qemu_stderr_sha256', 'checks', 'guest_inputs', 'versions'].sort());
  assert.equal(receipt.schema, 2);
  assert.equal(receipt.kind, 'alpha2-vm-sanitized');
  assert.equal(receipt.verified_before_export, true);
  assert.deepEqual(receipt.source, publicSource(receipt.source));
  verifySource(receipt.source, expectedSha);
  assert(['kvm', 'tcg'].includes(receipt.accelerator));
  assert.deepEqual(receipt.checks, checks);
  assert.deepEqual(Object.keys(receipt.artifacts), artifacts);
  for (const value of [...Object.values(receipt.artifacts), receipt.console_sha256, receipt.qemu_stderr_sha256]) assert.match(value, /^[a-f0-9]{64}$/);
  assert.equal(digest(versionsText(receipt.versions)), receipt.artifacts['packages.tsv']);
  assert.equal(digest(inputsText(receipt.guest_inputs)), receipt.artifacts['inputs.sha256']);
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, dir, expectedSha, destination] = process.argv.slice(2);
  if (mode === 'create') {
    const source = JSON.parse(read(dir, 'source.json'));
    const receipt = evidence(dir, source.sha);
    fs.writeFileSync(path.join(dir, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
    fs.writeFileSync(path.join(dir, 'receipt.sha256'), `${hash(dir, 'receipt.json')}  receipt.json\n`);
  } else if (mode === 'export') {
    exportEvidence(dir, expectedSha, destination);
    console.log(`Verified full evidence and exported sanitized receipt for ${expectedSha}`);
  } else if (mode === 'verify-export') {
    verifyExport(dir, expectedSha);
    console.log(`Verified sanitized alpha2 VM receipt for ${expectedSha}`);
  } else {
    assert.equal(mode, 'verify');
    verify(dir, expectedSha);
    console.log(`Verified alpha2 VM receipt for ${expectedSha}`);
  }
}
