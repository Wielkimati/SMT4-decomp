#ifndef SMT4_RESOURCE_WORKER_FILE_CLEANUP_H
#define SMT4_RESOURCE_WORKER_FILE_CLEANUP_H
#include <stdint.h>

/* EU ARM 0x002BB81C and shared entry 0x002BB824. Both return object.
 * The shared entry's incoming r1 is dead. Handle words 0/1 are preserved.
 * A tagged nonzero handle reaches the external diagnostic boundary first. */
uint32_t *smt4_worker_file_cleanup(uint32_t *object);
uint32_t *smt4_worker_file_cleanup_shared(uint32_t *object);
/* EU ARM 0x00354FA4: cleanup then null-safe object release. */
void smt4_worker_file_destroy(uint32_t *object);
/* EU ARM 0x002B2580: null-safe forwarding to resource release 0x002C43B4. */
void smt4_worker_object_release(uint32_t *object);
/* EU ARM 0x002B9450: nonnull backend's vtable +0x2C. Return is unconsumed. */
void smt4_worker_file_close(uint32_t backend);
#endif
