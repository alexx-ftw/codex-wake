import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {test} from 'node:test';
import {artifacts, digest, evidence, sourcePaths} from './receipt.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const sha = '1'.repeat(40);
const result = {passed:true, phase:'corrected hazards and integrated systemd transaction', systemd_pid1:true,
  production_migration_qualified:false, transition:{passed:true,production_migration_qualified:false,
    uncertain_delivery_attempts_measured:true,uncertain_delivery_attempts:1,uncertain_delivery_retries:0,
    uncertain_response_loss_exercised:true,delivery_positive_controls:2}};
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wake-lab-test-'));
  t.after(() => fs.rmSync(dir, {recursive:true, force:true}));
  for (const name of artifacts) fs.writeFileSync(path.join(dir, name), name);
  fs.writeFileSync(path.join(dir, 'source.json'), JSON.stringify({sha,tree:'2'.repeat(40)}));
  fs.writeFileSync(path.join(dir, 'SHA256SUMS'), artifacts.map(name => `${digest(fs.readFileSync(path.join(dir,name)))}  ${name}\n`).join(''));
  fs.writeFileSync(path.join(dir, 'nonce.txt'), '12345678-1234-1234-1234-123456789abc\n');
  fs.writeFileSync(path.join(dir, 'accelerator.txt'), 'tcg\n');
  fs.writeFileSync(path.join(dir, 'qemu.stderr'), '');
  fs.writeFileSync(path.join(dir, 'console.log'), `VM_SOURCE_SHA=${sha}\nVM_NONCE=12345678-1234-1234-1234-123456789abc\nVM_RESULT=${JSON.stringify(result)}\nVM_EXIT=0\n`);
  return dir;
}
test('receipt rejects changed inputs, wrong SHA, stale nonce and incomplete guest results', t => {
  const dir = fixture(t);
  assert.equal(evidence(dir,sha).accelerator,'tcg');
  assert.throws(() => evidence(dir,'3'.repeat(40)), /wrong source/);
  const consoleFile = path.join(dir,'console.log'), good = fs.readFileSync(consoleFile,'utf8');
  for (const bad of [good.replace('VM_EXIT=0','VM_EXIT=1'), good+'VM_EXIT=0\n',
    good.replace('12345678-1234','87654321-4321'), good.replace('"passed":true','"passed":false'),
    good.replace(/^VM_RESULT=.*\n/m,''), good.replace('"production_migration_qualified":false','"production_migration_qualified":true'),
    good.replace('"uncertain_delivery_attempts_measured":true','"uncertain_delivery_attempts_measured":false'),
    good.replace('"uncertain_delivery_retries":0','"uncertain_delivery_retries":1'),
    good.replace('VM_EXIT=0\n','').replace('VM_RESULT=', 'VM_EXIT=0\nVM_RESULT=')]) {
    fs.writeFileSync(consoleFile,bad);
    assert.throws(() => evidence(dir,sha));
  }
  fs.writeFileSync(consoleFile,good);
  fs.appendFileSync(path.join(dir,'kernel'),'corrupted');
  assert.throws(() => evidence(dir,sha), /changed artifact/);
});
test('CLI verifier checks source hashes against actual Git objects, beyond the checksum chain', t => {
  const dir=fixture(t), repo=path.resolve(here,'../..');
  const git=args=>execFileSync('git',args,{cwd:repo});
  const exact=git(['rev-parse','HEAD']).toString().trim();
  const files=git(['ls-tree','-rz','--name-only',exact,'--',...sourcePaths]).toString().split('\0').filter(Boolean);
  const source={sha:exact,tree:git(['rev-parse',`${exact}^{tree}`]).toString().trim(),
    files:Object.fromEntries(files.map(f=>[f,digest(git(['show',`${exact}:${f}`]))]))};
  fs.writeFileSync(path.join(dir,'console.log'),fs.readFileSync(path.join(dir,'console.log'),'utf8').replace(sha,exact));
  const create=()=>{
    fs.writeFileSync(path.join(dir,'source.json'),JSON.stringify(source));
    fs.writeFileSync(path.join(dir,'SHA256SUMS'),artifacts.map(n=>`${digest(fs.readFileSync(path.join(dir,n)))}  ${n}\n`).join(''));
    execFileSync(process.execPath,[path.join(here,'receipt.mjs'),'create',dir]);
  };
  create();
  execFileSync(process.execPath,[path.join(here,'receipt.mjs'),'verify',dir,exact],{stdio:'pipe'});
  source.files[files[0]]='0'.repeat(64);
  create();
  assert.notEqual(spawnSync(process.execPath,[path.join(here,'receipt.mjs'),'verify',dir,exact]).status,0);
});
test('spaced JSON is accepted before exit and rejected after exit', t => {
  const dir=fixture(t), file=path.join(dir,'console.log');
  const spaced=JSON.stringify(result).replaceAll(':', ': ').replaceAll(',', ', ');
  const before=fs.readFileSync(file,'utf8').replace(JSON.stringify(result),spaced);
  fs.writeFileSync(file,before);
  assert.equal(evidence(dir,sha).result.passed,true);
  fs.writeFileSync(file,before.replace(`VM_RESULT=${spaced}\nVM_EXIT=0`, `VM_EXIT=0\nVM_RESULT=${spaced}`));
  assert.throws(()=>evidence(dir,sha), /result after exit/);
});
test('real shell launcher uses isolated TCG/KVM arguments and fails closed on timeout', t => {
  const dir = fixture(t), bin=path.join(dir,'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin,'timeout'), '#!/bin/sh\nif [ "${FAKE_TIMEOUT:-0}" = 1 ]; then exit 124; fi\nshift 4\nexec "$@"\n', {mode:0o755});
  fs.writeFileSync(path.join(bin,'qemu-system-x86_64'), `#!/usr/bin/env node
const fs=require('fs'); const a=process.argv.slice(2); fs.writeFileSync('args.json',JSON.stringify(a));
const cmd=a[a.indexOf('-append')+1]; const nonce=cmd.match(/wake_lab_nonce=([a-f0-9-]+)/)[1];
console.log('VM_SOURCE_SHA=${sha}');console.log('VM_NONCE='+nonce);
console.log('VM_RESULT=${JSON.stringify(result)}');console.log('VM_EXIT=0');
`, {mode:0o755});
  for (const accel of ['tcg','kvm']) {
    const env={...process.env,PATH:bin+':'+process.env.PATH,LAB_ACCEL:accel};
    execFileSync('bash',[path.join(here,'run.sh'),dir],{env,stdio:'pipe'});
    const args=JSON.parse(fs.readFileSync(path.join(dir,'args.json')));
    assert.equal(args[args.indexOf('-accel')+1],accel);
    assert.equal(args[args.indexOf('-nic')+1],'none');
    assert.equal(args[args.indexOf('-monitor')+1],'none');
    assert(args.includes('-nodefaults'));
    for(const flag of ['-virtfs','-fsdev','-drive','-hda','-blockdev','-chardev','-netdev','-net','-vnc','-qmp']) assert(!args.includes(flag),flag);
    assert.equal(evidence(dir,sha).accelerator,accel);
  }
  fs.unlinkSync(path.join(dir,'receipt.json'));
  const run=spawnSync('bash',[path.join(here,'run.sh'),dir],{env:{...process.env,PATH:bin+':'+process.env.PATH,FAKE_TIMEOUT:'1'}});
  assert.equal(run.status,124);
  assert(!fs.existsSync(path.join(dir,'receipt.json')));
});
test('imported guest sources retain environment and policy guards', () => {
  const source=['vm.rs','integrated.rs','persistent.rs','hazards.rs','transition.rs'].map(f=>fs.readFileSync(path.join(here,f),'utf8')).join('\n');
  for(const p of ['/home/eros/', 'cleanup-uninstalled', 'remove-service', '"uninstall"']) assert(!source.includes(p),p);
  for(const [key,value] of Object.entries({HOME:'/lab',CODEX_HOME:'/lab/codex',TMPDIR:'/lab/tmp',
    XDG_STATE_HOME:'/lab/state',XDG_CONFIG_HOME:'/lab/config',XDG_DATA_HOME:'/lab/data',XDG_CACHE_HOME:'/lab/cache'})) {
    assert(source.includes(key==='HOME'?'.env("HOME", P)':`.env("${key}", "${value}")`),key);
  }
  assert(source.includes('.env_clear()'));
  assert(source.includes('/proc/1/exe'));
  assert(source.includes('wake_lab_vm=1'));
  assert(fs.readFileSync(path.join(here,'fence.bpf.c'),'utf8').includes('SEC("lsm/task_kill")'));
  const build=fs.readFileSync(path.join(here,'build.sh'),'utf8');
  assert(build.includes('--owner=0:0'));
  assert(!build.includes('bpf prog load'));
  const ci=fs.readFileSync(path.join(here,'ci.sh'),'utf8');
  assert(ci.includes('git archive "$expected"'));
  assert(!/--(?:privileged|volume|mount)\b/.test(ci));
});
