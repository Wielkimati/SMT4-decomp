#ifndef SMT4_RESOURCE_LIFECYCLE_H
#define SMT4_RESOURCE_LIFECYCLE_H
#include <stdint.h>

/* Original 67 x 16-byte registry: u32 path/address/size, u8 policy, 3 opaque bytes.
 * Addresses are original 32-bit values. This is not a native host loader API.
 */
extern uint8_t smt4_table_resource_registry[67 * 16];
uint32_t resource_load_if_dynamic(uint32_t resource_id);
uint32_t resource_request_if_dynamic(uint32_t resource_id);
uint32_t resource_release_if_dynamic(uint32_t resource_id);
void resource_load_complete(uint32_t address, uint8_t *entry, uint32_t size);
uint32_t resource_load_bulk(void);

/* Synchronous orchestration is in resource_sync.c; asynchronous orchestration
 * is in resource_request.c. Release routing is in resource_release.c; its
 * synchronization/address-conversion/allocator dependencies remain unrecovered.
 * Older isolated checkers intercept these backends.
 * size_out points to four writable little-endian bytes.
 */
uint32_t smt4_resource_load(uint32_t path, uint8_t *size_out, uint32_t options);
void smt4_resource_release(uint32_t address);
void smt4_resource_request(uint32_t path, uint8_t *address_out, uint32_t options,
                          void (*complete)(uint32_t, uint8_t *, uint32_t), uint8_t *entry);
#endif
