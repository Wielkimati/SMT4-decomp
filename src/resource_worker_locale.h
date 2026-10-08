#ifndef SMT4_RESOURCE_WORKER_LOCALE_H
#define SMT4_RESOURCE_WORKER_LOCALE_H
#include <stdint.h>

/* EU default locale. Valid output/state storage and the private reference
 * mapping are required; locale selection/initialization is a separate contract. */
uint32_t smt4_worker_locale_map(int32_t index); /* 0x00100F9C Thumb */
uint32_t smt4_worker_locale_decode(uint16_t *out, uint32_t byte,
                                  uint32_t state[2]); /* 0x00100FC8 Thumb */
extern const uint16_t smt4_worker_locale_mapping[7150]; /* 0x0041CAA0 */
#endif
