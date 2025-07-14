#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, char[256]);
} filename_map SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    u64 pid_tgid;
    char filename[256];

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    // Read the filename first
    bpf_probe_read_kernel_str(&filename, sizeof(filename), BPF_CORE_READ(name, name));
    
    // Check if filename is "lala"
    if (bpf_strncmp(filename, 4, "lala") == 0) {
        bpf_printk("FOUND FILE: lala\n");
        // Store filename in map for kretprobe
        bpf_map_update_elem(&filename_map, &pid_tgid, &filename, BPF_ANY);
    }

    // bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;
    u64 pid_tgid;
    char *filename;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    
    // Lookup filename from map
    filename = bpf_map_lookup_elem(&filename_map, &pid_tgid);
    if (filename && filename[0] != '\0') {
        bpf_printk("KPROBE EXIT: pid = %d, ret = %ld, filename = %s\n", pid, ret, filename);
        
        // Clean up the map entry
        bpf_map_delete_elem(&filename_map, &pid_tgid);
    } 
    
    return 0;
}