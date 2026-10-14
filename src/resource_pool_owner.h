#ifndef SMT4_RESOURCE_POOL_OWNER_H
#define SMT4_RESOURCE_POOL_OWNER_H
#include <stdint.h>
/* EU ARM 0x0014636C. Initializes selected fields of a mapped 0x130-byte object;
 * untouched bytes are preserved. Returns the original object address. */
uint32_t *smt4_resource_pool_object_construct(uint32_t *object);
/* EU ARM 0x003567F0 / 0x00356844. Teardown visits five owned file slots,
 * then the +F4 and +B8 pools; disposal returns the object to the pool loaded
 * from global state+4 after virtual teardown. Slots are not cleared. */
void smt4_resource_pool_object_dispose(uint32_t *object, uint32_t unused, uint32_t payload);
uint32_t *smt4_resource_pool_object_teardown(uint32_t *object, uint32_t unused, uint32_t payload);
/* EU ARM 0x002A458C. Changes the base vtable and, if diagnostics return,
 * detaches the list at +10. Does not free its nodes or backing storage. */
/* All three entries consume incoming r2 (payload). Base/object teardown also
 * return scratch r2: the last detached node, the last diagnostic's returned r2,
 * or unchanged incoming r2. Their assembly callers preserve this extra return;
 * an ordinary C call only exposes the r0 pointer result. Virtual file disposal
 * may replace r2 before the embedded pools. */
uint32_t *smt4_resource_pool_base_teardown(uint32_t *pool, uint32_t unused, uint32_t payload);
/* EU ARM 0x002ADCD8. Publishes output only after nonnegative initialization.
 * descriptor points to four readable words; all pointers use the original ABI. */
uint32_t smt4_resource_pool_owner_create(uint32_t **output,
    const uint32_t *descriptor, uint32_t a, uint32_t b,
    uint32_t c, uint32_t d, uint32_t e);
/* EU ARM 0x001270C4. Alternate request layout, virtual handle wrapper, then
 * the same initializer/lifetime chain. Descriptor supplies twelve bytes. */
uint32_t smt4_resource_pool_alternate_create(uint32_t **output,
    uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e,
    const uint32_t *descriptor);
/* EU ARM 0x003567A4. Ignores receiver; on exhaustion closes handle (including
 * zero), returns D8604659, and preserves output. Otherwise publishes a file. */
uint32_t smt4_resource_pool_wrap_handle(uint32_t *object,
    uint32_t **output, uint32_t handle);
/* EU ARM 0x002B5DD0. Writes 13 TLS command words and issues SVC 0x32.
 * Nonnegative kernel status publishes command[3], then returns command[1],
 * even if the service status is negative. Descriptor shifts wrap at 32 bits.
 * TLS/kernel behavior remains external; buffer contents are not read here. */
uint32_t smt4_resource_pool_owner_request(uint32_t *service, uint32_t *handle,
    uint32_t word1, uint32_t word2, uint32_t type1, const uint32_t *data1,
    uint32_t size1, uint32_t type2, const uint32_t *data2, uint32_t size2,
    uint32_t word7, uint32_t word8);
/* EU ARM 0x00145E9C. Header reads, views, pools and ownership publication.
 * Mapped original pointers; unsigned capacity arithmetic intentionally wraps. */
uint32_t smt4_resource_pool_owner_initialize(uint32_t *object, uint32_t *file,
    uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e); /* 0x00145E9C */
uint32_t smt4_resource_pool_object_query(uint32_t *output); /* 0x00145E7C */
/* Recovered query accessor/IPC. TLS and kernel responses remain external.
 * Nonnegative kernel status publishes command[2] regardless of service status. */
uint32_t smt4_resource_pool_query_service(void); /* 0x002BBD3C */
uint32_t smt4_resource_pool_query_value(uint32_t *service, uint32_t *output); /* 0x0014F42C */
/* Remaining original-game boundary, not a native replacement. */
void smt4_resource_pool_initialize_diagnostic(uint32_t result, uint32_t site); /* 0x002BBD70 */
#endif
