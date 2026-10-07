/* A08 research adapter, NOT recovered game source or a native resource service. */
#ifndef SMT4_HOST_NKM_ADDRESS_SPACE_H
#define SMT4_HOST_NKM_ADDRESS_SPACE_H
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define SMT4_HOST_API __declspec(dllexport)
#else
#define SMT4_HOST_API
#endif

/* Host pointers live only in this adapter descriptor, never in registry bytes.
 * Each region is one stable backing object. Regions must not overlap or wrap.
 * The caller owns the descriptors/bytes and keeps them unchanged during eval.
 */
typedef struct {
    uint32_t address;
    uint32_t size;
    const uint8_t *bytes;
} smt4_host_region;

typedef struct {
    const smt4_host_region *regions;
    size_t region_count;
    uint32_t registry_address;
    uint32_t read_budget;
} smt4_host_space;

enum smt4_host_operation {
    SMT4_HOST_SELECT, SMT4_HOST_PAYLOAD, SMT4_HOST_COUNT,
    SMT4_HOST_RESOURCE, SMT4_HOST_LOOKUP, SMT4_HOST_PAIRS
};
enum smt4_host_status {
    SMT4_HOST_OK, SMT4_HOST_BAD_MAP, SMT4_HOST_UNMAPPED,
    SMT4_HOST_ALIGNMENT, SMT4_HOST_ADDRESS_WRAP, SMT4_HOST_BUDGET,
    SMT4_HOST_BAD_OPERATION
};

/* On success value is a u32 result/address, never a host pointer. On failure
 * value stays untouched: faults are adapter diagnostics, not game returns.
 * reads (optional) receives completed logical loads, including repeated count
 * loads. At most read_budget loads; at most 64 regions. No memory writes,
 * loading, allocation, ownership transfer, or synchronization are performed.
 * Missing section is a successful zero helper result / 50 pair result, but
 * the section-2 lookup still attempts its unconditional payload halfword read.
 */
SMT4_HOST_API int smt4_host_eval(const smt4_host_space *space,
    uint32_t operation, uint32_t arg0, uint32_t arg1,
    uint32_t *value, uint32_t *reads);
#endif
