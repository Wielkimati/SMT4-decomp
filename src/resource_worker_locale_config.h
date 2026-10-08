#ifndef SMT4_RESOURCE_WORKER_LOCALE_CONFIG_H
#define SMT4_RESOURCE_WORKER_LOCALE_CONFIG_H
#include <stdint.h>

/* EU Thumb contracts. Mapped 32-bit storage is required; no host validation.
 * Multi-bit queries write 42 bytes. Singleton queries return a private name.
 * Encoded names require 41 readable bytes, even for unselected categories.
 * Ordinary configuration can publish earlier categories before returning zero.
 * See docs/recovery/resource-worker-locale-config.md for the bounded domain. */
uint8_t *smt4_worker_locale_query(uint8_t *output, uint32_t mask); /* 0x002C6AA8 */
uint8_t *smt4_worker_locale_configure(uint8_t *output, uint32_t mask,
                                    const uint8_t *name); /* 0x002C6B46 */
uint8_t *smt4_worker_locale_set_name(uint8_t *output, uint32_t mask,
                                   const uint8_t *name); /* 0x002C6BAA */
extern const uint8_t smt4_worker_locale_default_name[]; /* 0x002C6C40 */
extern const uint8_t smt4_worker_locale_fixed_table[]; /* 0x0042A184 */
#endif
