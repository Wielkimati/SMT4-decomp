#ifndef SMT4_RESOURCE_SYNC_H
#define SMT4_RESOURCE_SYNC_H
#include <stdint.h>

/* Original 32-bit addresses; see docs/recovery/resource-sync.md. */
uint32_t smt4_resource_load_sync(uint32_t path, uint8_t *size, uint32_t flags,
                                uint32_t parameter);
uint32_t smt4_resource_load(uint32_t path, uint8_t *size, uint32_t flags);

/* Descriptor words retain original offsets; unknown fields are not retyped. */
void smt4_file_mark_cleanup(uint32_t *descriptor);
uint32_t smt4_file_set_flags(uint32_t *descriptor, uint32_t value);
uint32_t smt4_file_set_parameter(uint32_t *descriptor, uint32_t value);
uint32_t smt4_file_failed(const uint32_t *descriptor);

/* Unrecovered dependency boundary. Names describe observed roles only. */
extern uint8_t smt4_resource_path_mode;
extern const char smt4_resource_path_format[];
void smt4_resource_clear(void *buffer, uint32_t length);
uint32_t smt4_resource_path_has_prefix(uint32_t path);
int smt4_resource_format(char *destination, const char *format, ...);
uint32_t *smt4_file_create(const char *path, uint32_t mode);
void smt4_file_wait(uint32_t *descriptor);
#endif
