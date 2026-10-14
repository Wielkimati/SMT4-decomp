#ifndef SMT4_RESOURCE_GLOBAL_STARTUP_H
#define SMT4_RESOURCE_GLOBAL_STARTUP_H
#include <stdint.h>

/* EU 0x003F3568. Original mapped globals/backing storage must be writable.
 * Constructs the registry, global lock and three pools. No allocation or OS
 * service creation. Reinitializing live owners is not a supported lifetime. */
uint32_t smt4_resource_global_startup(void);
#endif
