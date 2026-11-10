// Guest-only experiment. The host compiles this object but never loads it.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";
#define SIGCONT 18
struct cfg { __u32 uid, controller; __u64 dev, directory, database, lifecycle_dev, lifecycle_inode, manager_inode; char socket_path[108]; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct cfg); } policy_cfg SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,__u32); } armed SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,__u64[7]); } counters SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,7); __type(key,__u32); __type(value,__u64[7]); } last_denial SEC(".maps");
struct identity { __u64 dev, ino; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,8); __type(key,__u32); __type(value,struct identity); } allowed_exec SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,64); __type(key,__u32); __type(value,struct identity); } protected_inodes SEC(".maps");
static __always_inline struct cfg *old(__u32 bit) {
 __u32 zero=0; __u32 *a=bpf_map_lookup_elem(&armed,&zero);struct cfg *c=bpf_map_lookup_elem(&policy_cfg,&zero);
 if(!a||!c||!(*a&bit))return 0;
 struct task_struct *t=bpf_get_current_task_btf();const struct cred *cr=BPF_CORE_READ(t,cred);
 __u32 uid=BPF_CORE_READ(cr,uid.val),euid=BPF_CORE_READ(cr,euid.val),suid=BPF_CORE_READ(cr,suid.val),fsuid=BPF_CORE_READ(cr,fsuid.val);
 if((uid==0||uid==40001)&&euid==uid&&suid==uid&&fsuid==uid)return 0;
 // No old-UID executable bypass; approved successor runs under another UID.
 return c;
}
static __always_inline int deny(int n){__u32 k=n; __u64 (*d)[7]=bpf_map_lookup_elem(&last_denial,&k);if(d){struct task_struct*t=bpf_get_current_task_btf();const struct cred*cr=BPF_CORE_READ(t,cred);(*d)[0]=bpf_get_current_pid_tgid();(*d)[1]=BPF_CORE_READ(cr,uid.val);(*d)[2]=BPF_CORE_READ(cr,euid.val);(*d)[3]=BPF_CORE_READ(cr,suid.val);(*d)[4]=BPF_CORE_READ(cr,fsuid.val);(*d)[5]=BPF_CORE_READ(t,mm,exe_file,f_inode,i_ino);(*d)[6]=BPF_CORE_READ(t,mm,exe_file,f_inode,i_sb,s_dev);}__u32 z=0;__u64 (*s)[7]=bpf_map_lookup_elem(&counters,&z);if(s)__sync_fetch_and_add(&(*s)[n],1);return -13;}
static __always_inline int dbname(struct dentry *d){char b[32]={};const unsigned char *name=BPF_CORE_READ(d,d_name.name);bpf_core_read_str(b,sizeof(b),name);return !__builtin_memcmp(b,"state.sqlite3",13)&&(b[13]==0||b[13]=='-');}
static __always_inline int resource(struct cfg *c,struct dentry *d){struct inode *i=BPF_CORE_READ(d,d_inode);if(i){__u64 ino=BPF_CORE_READ(i,i_ino),dev=BPF_CORE_READ(i,i_sb,s_dev);
// The pinned 6.12 verifier loses the bound of clang's 32-bit induction variable.
#pragma unroll
for(__u32 k=0;k<64;k++){struct identity*v=bpf_map_lookup_elem(&protected_inodes,&k);if(v&&v->ino&&v->ino==ino&&v->dev==dev)return 1;}}if(i&&BPF_CORE_READ(i,i_ino)==c->database&&BPF_CORE_READ(i,i_sb,s_dev)==c->dev)return 1;struct inode *p=BPF_CORE_READ(d,d_parent,d_inode);return BPF_CORE_READ(p,i_ino)==c->directory&&BPF_CORE_READ(p,i_sb,s_dev)==c->dev&&dbname(d);}
SEC("lsm/file_permission") int BPF_PROG(file_write,struct file *f,int mask,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&(mask&(2|8))&&resource(c,BPF_CORE_READ(f,f_path.dentry))?deny(0):0;}
SEC("lsm/path_truncate") int BPF_PROG(path_truncate_seal,const struct path *p,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&resource(c,BPF_CORE_READ(p,dentry))?deny(0):0;}
SEC("lsm/file_truncate") int BPF_PROG(file_truncate_seal,struct file *f,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&resource(c,BPF_CORE_READ(f,f_path.dentry))?deny(0):0;}
SEC("lsm/inode_setattr") int BPF_PROG(setattr_seal,struct mnt_idmap *idmap,struct dentry *d,struct iattr *attr,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&(BPF_CORE_READ(attr,ia_valid)&8)&&resource(c,d)?deny(0):0;}
SEC("lsm/task_fix_setuid") int BPF_PROG(uid_seal,struct cred *new_cred,const struct cred *old_cred,int flags,int ret){if(ret)return ret;
 // Privileged root may stage fsuid while systemd prepares a child; root is trusted.
 if(BPF_CORE_READ(old_cred,uid.val)==0&&BPF_CORE_READ(old_cred,euid.val)==0&&BPF_CORE_READ(old_cred,suid.val)==0)return 0;
 struct cfg*c=old(16);if(!c)return 0;
 struct task_struct*t=bpf_get_current_task_btf();struct inode*i=BPF_CORE_READ(t,mm,exe_file,f_inode);
 // systemd and its executor temporarily switch EUID during keyring setup.
 if((BPF_CORE_READ(old_cred,uid.val)==0||BPF_CORE_READ(old_cred,euid.val)==0)&&BPF_CORE_READ(old_cred,suid.val)==0&&(BPF_CORE_READ(i,i_ino)==c->lifecycle_inode||BPF_CORE_READ(i,i_ino)==c->manager_inode)&&BPF_CORE_READ(i,i_sb,s_dev)==c->lifecycle_dev)return 0;
 return deny(0);}
SEC("lsm/inode_link") int BPF_PROG(link_seal,struct dentry *src,struct inode *dir,struct dentry *dst,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&(resource(c,src)||resource(c,dst))?deny(0):0;}
SEC("lsm/file_lock") int BPF_PROG(file_lock,struct file *f,unsigned int cmd,int ret){if(ret)return ret;if(cmd==2)return 0;struct cfg*c=old(2);if(c&&resource(c,BPF_CORE_READ(f,f_path.dentry))){deny(1);return -1;}return 0; /* EPERM: SQLite treats EACCES as contention. */}
SEC("lsm/inode_create") int BPF_PROG(create,struct inode*dir,struct dentry*d,umode_t mode,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&BPF_CORE_READ(dir,i_ino)==c->directory&&BPF_CORE_READ(dir,i_sb,s_dev)==c->dev&&dbname(d)?deny(0):0;}
SEC("lsm/inode_unlink") int BPF_PROG(unlink,struct inode*dir,struct dentry*d,int ret){if(ret)return ret;struct cfg*c=old(2);return c&&resource(c,d)?deny(0):0;}
SEC("lsm/socket_sendmsg") int BPF_PROG(send,struct socket*s,struct msghdr*msg,int size,int ret){
 if(ret)return ret;struct cfg*c=old(1);if(!c)return 0;struct sock*sk=BPF_CORE_READ(s,sk);if(BPF_CORE_READ(sk,__sk_common.skc_family)!=1)return 0;
 struct pid*pid=BPF_CORE_READ(sk,sk_peer_pid);if(BPF_CORE_READ(pid,numbers[0].nr)!=c->controller)return 0;
 struct sock*peer=BPF_CORE_READ((struct unix_sock*)sk,peer);struct unix_address*a=BPF_CORE_READ((struct unix_sock*)peer,addr);if(!a)return 0;
 char path[108]={};const char*name=__builtin_preserve_access_index(&a->name[0].sun_path[0]);bpf_probe_read_kernel_str(path,sizeof(path),name);
 #pragma unroll
 for(int i=0;i<108;i++){if(path[i]!=c->socket_path[i])return 0;if(!path[i])return deny(2);}return 0;
}
// A closed guest manifest: old UID may only exec these immutable helper inodes.
SEC("lsm/bprm_check_security") int BPF_PROG(exec_seal,struct linux_binprm*b,int ret){
 if(ret)return ret;struct cfg*c=old(4);if(!c)return 0;
 struct inode*i=BPF_CORE_READ(b,file,f_inode);__u64 ino=BPF_CORE_READ(i,i_ino),dev=BPF_CORE_READ(i,i_sb,s_dev);
 #pragma unroll
 for(__u32 k=0;k<8;k++){struct identity*v=bpf_map_lookup_elem(&allowed_exec,&k);if(v&&v->ino&&v->ino==ino&&v->dev==dev)return 0;}
 return deny(3);
}
SEC("lsm/mmap_file") int BPF_PROG(map_seal,struct file*f,unsigned long reqprot,unsigned long prot,unsigned long flags,int ret){
 if(ret)return ret;struct cfg*c=old(2);return c&&f&&(prot&2)&&(flags&1)&&resource(c,BPF_CORE_READ(f,f_path.dentry))?deny(4):0;
}
SEC("lsm/file_mprotect") int BPF_PROG(protect_seal,struct vm_area_struct*v,unsigned long reqprot,unsigned long prot,int ret){
 if(ret)return ret;struct cfg*c=old(2);struct file*f=BPF_CORE_READ(v,vm_file);return c&&f&&(prot&2)&&(BPF_CORE_READ(v,vm_flags)&8)&&resource(c,BPF_CORE_READ(f,f_path.dentry))?deny(5):0;
}
SEC("lsm/task_alloc") int BPF_PROG(fork_seal,struct task_struct*t,unsigned long flags,int ret){
 if(ret)return ret;struct cfg*c=old(8);if(c&&(__u32)(bpf_get_current_pid_tgid()>>32)!=c->controller){deny(6);return -1;}return 0;
}
SEC("lsm/task_kill") int BPF_PROG(sigcont_seal,struct task_struct*p,struct kernel_siginfo*info,int sig,const struct cred*cred,int ret){
 if(ret)return ret;struct cfg*c=old(32);return c&&sig==SIGCONT?-13:0;
}
SEC("lsm/inode_rename") int BPF_PROG(rename_seal,struct inode*od,struct dentry*old_dentry,struct inode*nd,struct dentry*new_dentry,int ret){
 if(ret)return ret;struct cfg*c=old(2);return c&&(resource(c,old_dentry)||resource(c,new_dentry))?deny(0):0;
}
