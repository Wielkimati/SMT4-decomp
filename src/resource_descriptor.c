/* Four original descriptor contracts, EU ARM addresses recorded below. */
#include "resource_sync.h"

/* 0x002B0468: increment a cleanup-request word; this does not free memory. */
void smt4_file_mark_cleanup(uint32_t *descriptor)
{
    descriptor[2] += 1u;
}

/* 0x002B0478: only state zero accepts configuration. */
uint32_t smt4_file_set_flags(uint32_t *descriptor, uint32_t value)
{
    if (descriptor[0] != 0)
        return 0;
    descriptor[9] = value;
    return 1;
}

/* 0x0014E744: meaning of the parameter at +0x28 is not yet established. */
uint32_t smt4_file_set_parameter(uint32_t *descriptor, uint32_t value)
{
    if (descriptor[0] != 0)
        return 0;
    descriptor[10] = value;
    return 1;
}

/* 0x0014E634: equality with state 5, not a generic nonzero test. */
uint32_t smt4_file_failed(const uint32_t *descriptor)
{
    return descriptor[0] == 5;
}
