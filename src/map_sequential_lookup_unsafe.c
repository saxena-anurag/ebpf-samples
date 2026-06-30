// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Regression test for assign_valid_ptr svalue havoc bug (soundness).
//
// This program is intentionally UNSAFE and must be REJECTED by the verifier.
// It performs two sequential bpf_map_lookup_elem calls on a hash map with a
// null-check only on the first result. On the second lookup's null branch it
// dereferences the result without a null check -- an invalid memory access.
//
// With the assign_valid_ptr svalue bug, the verifier failed to havoc the
// signed value (svalue) of the destination register before constraining it.
// After the first lookup + null-check narrowed svalue to >0, the second
// lookup inherited that stale constraint, making the null branch appear
// unreachable (bottom). The verifier therefore skipped all safety checks
// on that path, allowing this unsafe program to pass verification.
//
// With the fix (havoc svalue before constraining), the second null branch
// is correctly analyzed and the verifier rejects the program.

#include "bpf.h"

__attribute__((section(".maps"), used))
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 2);
} map;

int func(void* ctx)
{
    uint32_t key_0 = 0;
    uint32_t key_1 = 1;

    // First lookup plus null check narrows r0 to non-null on this path.
    uint32_t* val_0 = bpf_map_lookup_elem(&map, &key_0);
    if (!val_0) {
        return -1;
    }

    // Second lookup result is nullable for hash maps.
    uint32_t* val_1 = bpf_map_lookup_elem(&map, &key_1);
    if (!val_1) {
        // BUG TRIGGER: dereference null pointer in the null branch.
        // Without the svalue havoc fix, the verifier marks this branch
        // as unreachable and misses the unsafe dereference.
        return (int)(*(volatile uint32_t*)val_1);
    }

    return (int)(*val_0 + *val_1);
}
