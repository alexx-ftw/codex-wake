import fs from 'node:fs';import path from 'node:path';import {execFileSync} from 'node:child_process';import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url)),root='/rootfs';
if(fs.existsSync(root))throw Error('retain previous rootfs; choose a fresh build directory');
for(const d of ['usr/bin','usr/lib','guest','etc','tmp','proc','sys','dev'])fs.mkdirSync(path.join(root,d),{recursive:true});
fs.chmodSync(path.join(root,'tmp'),0o1777);
for(const [p,t]of [['bin','usr/bin'],['lib','usr/lib'],['lib64','usr/lib'],['usr/lib64','lib'],['init','guest/vm-probe'],['usr/bin/sh','bash']])fs.symlinkSync(t,path.join(root,p));
function copy(from,to=from){to=to.replace(/^\/(?:usr\/)?lib64\//,'/usr/lib/').replace(/^\/lib\//,'/usr/lib/');const dest=path.join(root,to);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(from,dest);fs.chmodSync(dest,0o755);}
for(const [from,to]of [[path.join(here,'target/release/alpha2-vm-probe'),'/guest/vm-probe'],['/deps/legacy','/guest/legacy'],['/work/target/release/codex-wake','/guest/new-wake'],['/deps/codex','/guest/codex'],...['/usr/lib/x86_64-linux-gnu/libmount.so.1','/usr/lib/x86_64-linux-gnu/libkmod.so.2','/usr/lib/x86_64-linux-gnu/libseccomp.so.2','/usr/lib/systemd/systemd','/usr/lib/systemd/systemd-executor','/usr/lib/systemd/systemd-shutdown','/usr/bin/systemctl','/usr/bin/systemd-run','/usr/bin/busctl','/usr/bin/dbus-daemon','/usr/bin/sha256sum','/usr/bin/sleep','/usr/bin/git','/usr/bin/rg','/usr/bin/node'].map(p=>[p,p]),['/usr/bin/true','/usr/bin/true'],['/usr/bin/strace','/usr/bin/strace'],['/usr/bin/bash','/usr/bin/bash'],['/usr/bin/bwrap','/usr/bin/bwrap'],['/usr/bin/false','/usr/bin/false']]){
 copy(from,to);let l='';try{l=execFileSync('/usr/bin/ldd',[from],{encoding:'utf8',stdio:['ignore','pipe','pipe']});}catch(e){if(!/not a dynamic executable|statically linked/.test(String(e.stdout)+String(e.stderr)))throw e;}for(const m of l.matchAll(/(?:=>\s+|^\s*)(\/[^\s]+)/gm))copy(m[1]);
}
fs.copyFileSync('/deps/fence.bpf.o',path.join(root,'guest/fence.bpf.o'));
fs.writeFileSync(path.join(root,'etc/passwd'),'root:x:0:0:root:/:/bin/sh\nfixture:x:40000:40000:fixture:/lab:/bin/sh\nnew:x:40001:40001:new:/lab:/bin/sh\n');
fs.writeFileSync(path.join(root,'etc/group'),'root:x:0:\nfixture:x:40000:\nnew:x:40001:\n');
fs.writeFileSync(path.join(root,'etc/nsswitch.conf'),'passwd: files\ngroup: files\nhosts: files\n');
console.log(JSON.stringify({rootfs:root,host_mounts:false,host_credentials:false}));

for(const d of ['etc/systemd/system','etc/dbus-1','run','var','lab'])fs.mkdirSync(path.join(root,d),{recursive:true});
fs.writeFileSync(path.join(root,'etc/machine-id'),'0123456789abcdef0123456789abcdef\n');
fs.writeFileSync(path.join(root,'etc/os-release'),'ID=wake-lab\nNAME=Wake-isolated-lab\n');
fs.writeFileSync(path.join(root,'etc/hostname'),'wake-lab\n');
fs.writeFileSync(path.join(root,'etc/dbus-1/system.conf'),'<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>');
fs.writeFileSync(path.join(root,'etc/systemd/system/dbus.service'),'[Unit]\nDefaultDependencies=no\n[Service]\nType=notify\nSockets=dbus.socket\nExecStartPre=/guest/vm-probe role dbus-dir\nExecStart=/usr/bin/dbus-daemon --nofork --nopidfile --systemd-activation --config-file=/etc/dbus-1/system.conf\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n');
fs.writeFileSync(path.join(root,'etc/systemd/system/lab-driver.service'),'[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nExecStart=/guest/vm-probe suite\nTimeoutStartSec=900\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n');
fs.writeFileSync(path.join(root,'etc/systemd/system/lab.target'),'[Unit]\nDefaultDependencies=no\nWants=dbus.socket dbus.service lab-driver.service\n');

fs.writeFileSync(path.join(root,'etc/systemd/system/dbus.socket'),'[Unit]\nDefaultDependencies=no\n[Socket]\nListenStream=/run/dbus/system_bus_socket\n');

const guestInputs=['legacy','new-wake','codex','vm-probe','fence.bpf.o'];
fs.copyFileSync('/work/source.json',path.join(root,'guest/source.json'));
guestInputs.push('source.json');
fs.writeFileSync(path.join(root,'guest/inputs.sha256'),guestInputs.map(n=>execFileSync('sha256sum',[path.join(root,'guest',n)],{encoding:'utf8'}).replace(root,'')).join(''));
