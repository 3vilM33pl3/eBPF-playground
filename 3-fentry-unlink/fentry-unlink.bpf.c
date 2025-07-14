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

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    __u64 pid = bpf_get_current_pid_tgid();

    char fname[256];

    // Safely read the filename string from kernel memory
    bpf_probe_read_kernel_str(fname, sizeof(fname), name->name);


    bpf_map_update_elem(&filename_map, &pid, fname, BPF_ANY);

    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    __u64 pid;

    pid = bpf_get_current_pid_tgid();

    // Lookup the filename from the map
    char *filename = bpf_map_lookup_elem(&filename_map, &pid);
    if (filename && bpf_strncmp(filename, 4, "lala") == 0) {
        bpf_printk("FOUND FILE: lala\n");
    }

    
    return 0;
}