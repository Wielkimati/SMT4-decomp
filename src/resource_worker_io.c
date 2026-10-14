/* EU worker's state-zero region. See docs/recovery/resource-worker-io.md. */
#include "resource_worker_io.h"
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");

static uint32_t *object(uint32_t *d)
{
    return (uint32_t *)(uintptr_t)d[0x12c / 4];
}

static uintptr_t method(uint32_t *o, uint32_t offset)
{
    return ((const uint32_t *)(uintptr_t)o[0])[offset / 4];
}

void smt4_worker_state0_io(uint32_t *d)
{
    uint32_t *o = smt4_worker_object_allocate(24);
    if (o) {
        o[1] = o[2] = o[3] = o[4] = o[5] = 0;
        o[0] = smt4_worker_file_construction[0];
        uint32_t offset = ((const uint32_t *)(uintptr_t)o[0])[-12];
        *(uint32_t *)((uintptr_t)o + offset) = smt4_worker_file_construction[3];
    }
    d[0x12c / 4] = (uint32_t)(uintptr_t)o;
    uint32_t *handle = (uint32_t *)((uintptr_t)o + 4);
    uint16_t path[262], *out = path;
    const char *in = (const char *)d + 0x2c;
    uint32_t state[2] = {0, 0};
    smt4_worker_path_is_initial(state);
    for (;;) {
        uint32_t bytes = smt4_worker_path_measure(in, 0x105, state);
        if (bytes == 0 || smt4_worker_path_convert(out, in, bytes, state) == 0)
            break;
        ++out;
        in += bytes;
    }
    *out = 0;
    handle[3] = handle[4] = handle[1] = handle[2] = 0;
    uint32_t result = smt4_worker_file_open(handle, path, 1);
    if (result >> 31)
        d[0] = 5;
    o = object(d);
    d[6] = (uint32_t)((uint64_t (*)(uint32_t *))method(o, 0x24))(o);
    o = object(d);
    ((void (*)(uint32_t *, uint64_t, uint32_t))method(o, 0x0c))(o, 0, 0);
    if (d[3] == 0) {
        uint32_t flags = d[9];
        uint32_t type = (flags == 1 || flags == 17) ? 0x10000 : 0x100;
        uint32_t direction = (flags == 16 || flags == 17) ? 0 : 1;
        d[3] = smt4_worker_data_allocate(type, 0x100, 0, d[6], d[10], direction);
    }
    smt4_worker_io_acquire(smt4_worker_io_lock_handle);
    smt4_worker_io_busy = 1;
    o = object(d);
    uint32_t bytes_read;
    result = ((uint32_t (*)(uint32_t *, uint32_t *, uint32_t, uint32_t))
              method(o, 0x28))(o, &bytes_read, d[3], d[6]);
    smt4_worker_io_busy = 0;
    /* Original 0x0011401C..0x00114044 retains release's scratch r2 through
     * the diagnostic call. Capture it explicitly; ordinary C void-call rules
     * otherwise lose this observable callback word. Release remains external. */
    register uint32_t release_r0 __asm__("r0") = smt4_worker_io_lock_handle;
    register uint32_t release_r2 __asm__("r2");
    __asm__ volatile ("bl smt4_worker_io_release"
                      : "+r" (release_r0), "=r" (release_r2)
                      : : "r1", "r3", "r12", "lr", "cc", "memory");
    uint32_t break_payload = release_r2;
    if (result >> 31)
        d[0] = 5;
    o = object(d);
    if (o[1] & ~UINT32_C(1)) {
        if (o[1] & 1)
            smt4_worker_file_preclose(o[1], 0, break_payload);
        smt4_worker_file_close(o[1] & ~UINT32_C(1));
        o[1] = 0;
    }
    o = object(d);
    if (o)
        /* In this adapted region's retained domain the same object's handle
         * is now zero or tag-only, so the destructor's diagnostic payload is
         * dead. A callback replacing d[0x12c/4] with another tagged object is
         * outside that domain; its post-service scratch r2 is not recovered. */
        ((void (*)(uint32_t *, uint32_t, uint32_t))method(o, 4))(o, 0, 0);
    /* State 3 / file-object clear / state 4 belong to the enclosing step. */
}
