#ifndef SMT4_RESOURCE_WORKER_PATH_H
#define SMT4_RESOURCE_WORKER_PATH_H
#include <stdint.h>

/* EU runtime conversion dependencies. Valid 32-bit mapped storage is required.
 * Locale construction and callback implementation have separate contracts;
 * resource_worker_locale.h describes the recovered default callback. */
uint32_t smt4_worker_path_is_initial(const uint32_t state[2]); /* 0x002B9486 Thumb */
uint32_t smt4_worker_path_measure(const char *, uint32_t, uint32_t state[2]); /* 0x002B9468 Thumb */
uint32_t smt4_worker_path_convert(uint16_t *, const char *, uint32_t, uint32_t state[2]); /* 0x002C63DC Thumb */
uint32_t smt4_worker_path_decode_byte(uint16_t *, uint32_t, uint32_t state[2]); /* 0x001008C8 Thumb */
uint32_t *smt4_worker_path_state_slot(uint32_t ignored, uint32_t slot); /* 0x002C6936 Thumb */
uint32_t *smt4_worker_path_error(void); /* 0x002C6894 ARM */
uint8_t *smt4_worker_locale_context(void); /* 0x002C6C48 ARM */
uint32_t *smt4_worker_locale_slot(void); /* 0x002C6C94 ARM */

extern uint8_t smt4_worker_locale_storage[]; /* 0x004EFCA0 */
extern uint8_t smt4_worker_path_states[]; /* 0x004EFCE4, eight bytes per slot */
extern uint32_t smt4_worker_path_error_storage; /* 0x004EFCE0 */
#endif
