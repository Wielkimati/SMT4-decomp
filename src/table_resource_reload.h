#ifndef SMT4_TABLE_RESOURCE_RELOAD_H
#define SMT4_TABLE_RESOURCE_RELOAD_H
#include <stdint.h>
#include "table_resource_copy.h"
void smt4_table_resource_reload(uint32_t id);
void smt4_table_reload_state_set(uint32_t value);
int32_t smt4_table_reload_state_get(void);
/* Caller must supply an index into readable original-address storage. */
uint32_t smt4_table_reload_gate(uint32_t index);
#endif
