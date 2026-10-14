/* Project-authored EU base v0 recovery; see resource-pool-object-initialize.md. */
#include "resource_pool_owner.h"
#include "resource_pool_initialize.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

uint32_t smt4_resource_pool_object_query(uint32_t *output)
{
    uint32_t service = smt4_resource_pool_query_service();
    return smt4_resource_pool_query_value(&service, output);
}

static uint32_t read_at(uint32_t *file, uint32_t *received, uint32_t offset,
                        uint32_t buffer, uint32_t bytes)
{
    const volatile uint32_t *vtable = (const volatile uint32_t *)(uintptr_t)file[0];
    return ((uint32_t (*)(uint32_t *, uint32_t *, int64_t, uint32_t,
                         uint32_t))(uintptr_t)vtable[0])
        (file, received, (int64_t)(int32_t)offset, buffer, bytes);
}

uint32_t smt4_resource_pool_owner_initialize(uint32_t *object, uint32_t *file,
    uint32_t a, uint32_t b, uint32_t storage, uint32_t capacity, uint32_t load)
{
    volatile uint32_t *w = object;
    uint32_t header[10], sizing[10], received, sized;
    uint32_t result = read_at(file, &received, 0, (uint32_t)(uintptr_t)header, 40);
    if (result >> 31)
        return result;
    if (received != 40)
        return UINT32_C(0xc8a04554);
    uint32_t first_bytes = a << 5;
    uint32_t extra = 0, required;
    if (load != 0) {
        result = read_at(file, &sized, 0, (uint32_t)(uintptr_t)sizing, 40);
        required = UINT32_MAX;
        if ((result >> 31) == 0 && sized == 40) {
            extra = sizing[2] + sizing[4] + sizing[6] + sizing[8];
            if ((extra >> 31) == 0)
                required = first_bytes + (b + b * 2u) * 8u + extra;
        }
    } else {
        required = first_bytes + (b + b * 2u) * 8u;
    }
    if (required > capacity)
        return UINT32_C(0xd8604659);
    uint32_t starts[4];
    if (load != 0) {
        uint32_t offset = received;
        for (unsigned i = 0; i != 4; ++i) {
            starts[i] = storage;
            result = read_at(file, &received, offset, storage, header[2 + 2*i]);
            if (result >> 31)
                return result;
            storage += header[2 + 2*i];
            offset += received;
        }
        w[0x78/4] = 0;
        w[0x70/4] = starts[0]; w[0x74/4] = header[2];
        w[0x7c/4] = (uint32_t)(uintptr_t)object;
        for (unsigned i = 1; i != 4; ++i) {
            unsigned n = (0x70 + 16*i)/4;
            w[n+2] = 0; w[n+1] = header[2+2*i]; w[n] = starts[i];
            w[n+3] = (uint32_t)(uintptr_t)object;
        }
    } else {
        for (unsigned i = 0; i != 4; ++i) {
            unsigned n = (0x70 + 16*i)/4;
            w[n+3] = header[1+2*i]; w[n] = 0;
            w[n+1] = header[2+2*i]; w[n+2] = (uint32_t)(uintptr_t)object;
        }
    }
    uint32_t address = (uint32_t)(uintptr_t)object;
    w[0x2c/4] = address + 0x70; w[0x20/4] = 0;
    w[0x28/4] = header[2] >> 2; w[0x24/4] = 0;
    w[0x3c/4] = address + 0x80; w[0x38/4] = header[4];
    w[0x30/4] = 0; w[0x34/4] = 0; w[0x48/4] = 0;
    w[0x54/4] = address + 0x90; w[0x64/4] = address + 0xa0;
    w[0x4c/4] = 0; w[0x50/4] = header[6] >> 2;
    w[0x58/4] = 0; w[0x5c/4] = 0; w[0x60/4] = header[8];
    smt4_resource_pool_initialize(object + 0xb8/4, 32, storage, first_bytes, 4, 0);
    smt4_resource_recursive_lock_initialize(object + 0xe8/4);
    smt4_resource_pool_initialize(object + 0xf4/4, 24, storage + first_bytes,
                                  (b + b * 2u) * 8u, 4, 0);
    smt4_resource_recursive_lock_initialize(object + 0x124/4);
    w[0xb0/4] = header[9];
    result = smt4_resource_pool_object_query(object + 1);
    if (result >> 31)
        smt4_resource_pool_initialize_diagnostic(result, UINT32_C(0x0014622c));
    int32_t value = (int32_t)w[1];
    unsigned slot = value < -8 ? 0 : value < 0 ? 1 : value == 0 ? 2 : value <= 8 ? 3 : 4;
    w[3 + slot] = (uint32_t)(uintptr_t)file;
    w[2] = (uint32_t)(uintptr_t)file;
    return 0;
}
