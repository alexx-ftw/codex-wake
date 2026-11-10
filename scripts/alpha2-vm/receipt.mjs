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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, dir, expectedSha] = process.argv.slice(2);
  if (mode === 'create') {
    const source = JSON.parse(read(dir, 'source.json'));
    const receipt = evidence(dir, source.sha);
    fs.writeFileSync(path.join(dir, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
    fs.writeFileSync(path.join(dir, 'receipt.sha256'), `${hash(dir, 'receipt.json')}  receipt.json\n`);
  } else {
    assert.equal(mode, 'verify');
    assert.equal(read(dir, 'receipt.sha256').toString(), `${hash(dir, 'receipt.json')}  receipt.json\n`);
    assert.deepEqual(JSON.parse(read(dir, 'receipt.json')), evidence(dir, expectedSha));
    const source = JSON.parse(read(dir, 'source.json'));
    const git = args => execFileSync('git', args, {cwd: path.resolve(fileURLToPath(new URL('../..', import.meta.url)))});
    assert.equal(git(['rev-parse', `${expectedSha}^{tree}`]).toString().trim(), source.tree);
    const files = git(['ls-tree', '-rz', '--name-only', expectedSha, '--', ...sourcePaths]).toString().split('\0').filter(Boolean);
    assert.deepEqual(Object.keys(source.files).sort(), files.sort());
    for (const file of files) assert.equal(digest(git(['show', `${expectedSha}:${file}`])), source.files[file], `source mismatch: ${file}`);
    console.log(`Verified alpha2 VM receipt for ${expectedSha}`);
  }
}
