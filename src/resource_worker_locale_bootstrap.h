#ifndef SMT4_RESOURCE_WORKER_LOCALE_BOOTSTRAP_H
#define SMT4_RESOURCE_WORKER_LOCALE_BOOTSTRAP_H
#include <stdint.h>

/* EU ARM 0x002AA858. Exact r0 bits, not a normalized strcmp result.
 * NUL-terminated inputs are required. When both pointers are word-aligned,
 * every containing four-byte word (including the terminating word) is read. */
uint32_t smt4_worker_locale_name_compare(const uint8_t *, const uint8_t *);
uint32_t smt4_worker_locale_select_bytes(uint32_t ignored, const uint8_t *name); /* 0x00138208 */
uint32_t smt4_worker_locale_select_other(uint32_t ignored, const uint8_t *name); /* 0x0014D908 */
void smt4_worker_locale_bootstrap(void); /* 0x0010236C */

/* Private reference data, supplied by the target link/fixture. */
extern const uint8_t smt4_worker_locale_byte_name[]; /* 0x0042A040: SJIS */
extern const uint8_t smt4_worker_locale_other_name[]; /* 0x0042A160: C */
extern const uint8_t smt4_worker_locale_byte_table[]; /* 0x0042A04C */
extern const uint8_t smt4_worker_locale_other_table[]; /* 0x0042A168 */
#endif
