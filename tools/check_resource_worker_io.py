"""Build and compare the EU worker's adapted state-zero I/O region."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover-clear", action="store_true", help="Execute allocation zeroing; implies --recover-allocation")
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--recover-allocation", action="store_true", help="Execute object/lower/data allocators with guarded storage and explicit raw/registration models")
    parser.add_argument("--recover-file-methods", action="store_true", help="Execute size/seek/read virtual adapters; implies --recover-allocation")
    parser.add_argument("--recover-locale-bootstrap", action="store_true", help="Execute locale bootstrap/selectors/name comparison; implies --recover-locale")
    parser.add_argument("--recover-locale", action="store_true", help="Execute default locale callback and private code mapping; implies --recover-path")
    parser.add_argument("--recover-path", action="store_true", help="Execute worker path conversion and locale/state/error accessors; implies --recover-file-cleanup")
    parser.add_argument("--recover-file-cleanup", action="store_true", help="Execute cleanup/destruction/close; implies --recover-file-open")
    parser.add_argument("--recover-file-open", action="store_true", help="Execute prefix/open dispatch with modeled backend; implies --recover-file-read")
    parser.add_argument("--recover-file-read", action="store_true", help="Execute lower read loop with modeled OS read; implies --recover-file-position")
    parser.add_argument("--recover-file-position", action="store_true", help="Execute lower size/cache, seek and position; implies --recover-file-methods")
    parser.add_argument("--mutant", choices=("open-early-return", "flags-bit-test", "short-read-size", "cached-close-handle", "advance-failed-conversion", "object-route", "object-size", "object-direction", "object-return", "data-backlink", "size-truncate", "size-error-sign", "seek-offset", "seek-origin", "seek-site", "read-receiver", "read-return", "cache-failure", "position-equality", "position-unsigned", "relative-carry", "origin-error", "size-output-failure", "loop-sign", "loop-count-failure", "loop-buffer", "loop-remaining", "loop-positive", "loop-zero", "prefix-sign", "prefix-limit", "prefix-last", "open-length", "open-status", "open-preserve", "cleanup-reload", "cleanup-tag-only", "cleanup-clear", "cleanup-return", "close-slot", "release-null", "path-initial", "path-limit", "path-error", "path-slot", "path-result", "path-mode", "locale-gap", "locale-trail", "locale-reset", "locale-yen", "bootstrap-offset", "bootstrap-empty", "bootstrap-compare", "config-mask", "config-byte", "config-order", "registry-vacancy", "registry-sign", "registry-reload", "break-clear", "break-payload", "break-reason", "break-svc", "break-prefix-payload", "init-count", "init-stride", "init-tail", "init-base", "init-startup-count"))
    parser.add_argument("--recover-locale-config", action="store_true", help="Execute locale category query/configuration; implies --recover-locale-bootstrap")
    parser.add_argument("--recover-prefix", action="store_true", help="Execute prefix registration/removal; implies --recover-locale-config")
    parser.add_argument("--recover-break", action="store_true", help="Execute break callback dispatch and SVC boundary; implies --recover-prefix")
    parser.add_argument("--recover-registry-initialize", action="store_true", help="Execute registry startup slice and array/record initialization; implies --recover-break")
    args = parser.parse_args()
    if args.recover_registry_initialize:
        args.recover_break = True
    if args.recover_break:
        args.recover_prefix = True
    if args.recover_prefix:
        args.recover_locale_config = True
    if args.recover_locale_config:
        args.recover_locale_bootstrap = True
    if args.recover_locale_bootstrap:
        args.recover_locale = True
    if args.recover_locale:
        args.recover_path = True
    if args.recover_path:
        args.recover_file_cleanup = True
    if args.recover_file_cleanup:
        args.recover_file_open = True
    if args.recover_file_open:
        args.recover_file_read = True
    if args.recover_file_read:
        args.recover_file_position = True
    if args.recover_file_position:
        args.recover_file_methods = True
    if args.recover_file_methods or args.recover_clear:
        args.recover_allocation = True
    output, project = local_path(args.output), local_path(args.project_dir)
    if output.exists():
        raise FileExistsError("Choose new output under local/")
    if not (project / "SMT4-EU.gpr").is_file():
        raise FileNotFoundError("Saved EU project required")
    code = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    check_hash(code, CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    tool_dir = ROOT / pins["directory"] / "bin"
    for name, expected in pins["executables"].items():
        check_hash(tool_dir / name, expected)
    java = java_command()
    output.mkdir(parents=True)
    source = ROOT / "src/resource_worker_io.c"
    allocation_sources = [ROOT / "src" / name for name in (
        "resource_worker_object_allocate.c", "resource_worker_data_allocate.c", "resource_allocate_lower.c")] if args.recover_allocation else []
    method_sources = [ROOT / "src/resource_worker_file_methods.c"] if args.recover_file_methods else []
    position_sources = [ROOT / "src/resource_worker_file_position.c"] if args.recover_file_position else []
    read_sources = [ROOT / "src/resource_worker_file_read.c"] if args.recover_file_read else []
    open_sources = [ROOT / "src/resource_worker_file_open.c"] if args.recover_file_open else []
    cleanup_sources = [ROOT / "src/resource_worker_file_cleanup.c"] if args.recover_file_cleanup else []
    path_sources = [ROOT / "src/resource_worker_path.c"] if args.recover_path else []
    locale_sources = [ROOT / "src/resource_worker_locale.c"] if args.recover_locale else []
    bootstrap_sources = [ROOT / "src/resource_worker_locale_bootstrap.c"] if args.recover_locale_bootstrap else []
    config_sources = [ROOT / "src/resource_worker_locale_config.c"] if args.recover_locale_config else []
    prefix_sources = [ROOT / "src/resource_worker_prefix.c"] if args.recover_prefix else []
    break_sources = [ROOT / "src/resource_break.c"] if args.recover_break else []
    initialize_sources = [ROOT / "src/resource_array_initialize.c", ROOT / "src/resource_worker_prefix_initialize.c"] if args.recover_registry_initialize else []
    initialize_mutant = args.mutant and args.mutant.startswith("init-")
    if initialize_mutant and not args.recover_registry_initialize:
        parser.error("Initialization faults require --recover-registry-initialize")
    break_mutant = args.mutant and args.mutant.startswith("break-")
    if break_mutant and not args.recover_break:
        parser.error("Break faults require --recover-break")
    prefix_mutant = args.mutant and (args.mutant.startswith("registry-") or args.mutant == "break-prefix-payload")
    if prefix_mutant and not args.recover_prefix:
        parser.error("Registry faults require --recover-prefix")
    config_mutant = args.mutant and args.mutant.startswith("config-")
    if config_mutant and not args.recover_locale_config:
        parser.error("Configuration faults require --recover-locale-config")
    bootstrap_mutant = args.mutant and args.mutant.startswith("bootstrap-")
    if bootstrap_mutant and not args.recover_locale_bootstrap:
        parser.error("Bootstrap faults require --recover-locale-bootstrap")
    locale_mutant = args.mutant and args.mutant.startswith("locale-")
    if locale_mutant and not args.recover_locale:
        parser.error("Locale faults require --recover-locale")
    path_mutant = args.mutant and args.mutant.startswith("path-")
    if path_mutant and not args.recover_path:
        parser.error("Path faults require --recover-path")
    cleanup_mutant = args.mutant in ("cleanup-reload", "cleanup-tag-only", "cleanup-clear", "cleanup-return", "close-slot", "release-null")
    if cleanup_mutant and not args.recover_file_cleanup:
        parser.error("Cleanup faults require --recover-file-cleanup")
    open_mutant = args.mutant in ("prefix-sign", "prefix-limit", "prefix-last", "open-length", "open-status", "open-preserve")
    if open_mutant and not args.recover_file_open:
        parser.error("Open faults require --recover-file-open")
    read_mutant = args.mutant and args.mutant.startswith("loop-")
    if read_mutant and not args.recover_file_read:
        parser.error("Read-loop faults require --recover-file-read")
    position_mutant = args.mutant in ("cache-failure", "position-equality", "position-unsigned", "relative-carry", "origin-error", "size-output-failure")
    if position_mutant and not args.recover_file_position:
        parser.error("Position faults require --recover-file-position")
    method_mutant = args.mutant and args.mutant.startswith(("size-", "seek-", "read-")) and not position_mutant
    if method_mutant and not args.recover_file_methods:
        parser.error("Method faults require --recover-file-methods")
    allocation_mutant = args.mutant and (args.mutant.startswith("object-") or args.mutant == "data-backlink")
    if allocation_mutant and not args.recover_allocation:
        parser.error("Allocation faults require --recover-allocation")
    if args.mutant:
        edits = {
            "open-early-return": ("if (result >> 31)\n        d[0] = 5;\n    o = object(d);\n    d[6]", "if (result >> 31) { d[0] = 5; return; }\n    o = object(d);\n    d[6]"),
            "flags-bit-test": ("(flags == 1 || flags == 17)", "(flags & 1)"),
            "short-read-size": ("smt4_worker_io_busy = 0;", "d[6] = bytes_read;\n    smt4_worker_io_busy = 0;"),
            "cached-close-handle": ("if (o[1] & 1)\n            smt4_worker_file_preclose(o[1], 0, break_payload);\n        smt4_worker_file_close(o[1] & ~UINT32_C(1));", "uint32_t saved = o[1];\n        if (saved & 1)\n            smt4_worker_file_preclose(saved, 0, break_payload);\n        smt4_worker_file_close(saved & ~UINT32_C(1));"),
            "advance-failed-conversion": ("break;\n        ++out;", "{ ++out; break; }\n        ++out;"),
            "object-route": ("(0x100, 0x100, 0, bytes, 1)", "(0x10000, 0x100, 0, bytes, 1)"),
            "object-size": ("0, bytes, 1)", "0, (uint16_t)bytes, 1)"),
            "object-direction": ("0, bytes, 1)", "0, bytes, 0)"),
            "object-return": ("return smt4_resource_allocate_lower(0x100, 0x100, 0, bytes, 1);", "return (uint32_t *)((uintptr_t)smt4_resource_allocate_lower(0x100, 0x100, 0, bytes, 1) + 4u);"),
            "data-backlink": ("user - 4u", "user - 8u"),
            "size-truncate": ("return size;", "return (uint32_t)size;"),
            "size-error-sign": ("if (result >> 31)\n        smt4_worker_file_diagnostic(result, 0x003DFC70);", "if (result != 0)\n        smt4_worker_file_diagnostic(result, 0x003DFC70);"),
            "seek-offset": ("origin, offset, origin)", "origin, (uint32_t)offset, origin)"),
            "seek-origin": ("origin, offset, origin)", "origin, offset, 0)"),
            "seek-site": ("0x00354F8C", "0x00354F84"),
            "read-receiver": ("file_read_lower(object + 1,", "file_read_lower(object,"),
            "read-return": ("return smt4_worker_file_read_lower(object + 1, count, buffer, bytes);", "return smt4_worker_file_read_lower(object + 1, count, buffer, bytes) ^ 1u;"),
        }
        edits.update({
            "cache-failure": ("handle[3] = 0;", "handle[3] = 1;"),
            "position-equality": ("(position ^ sign) >=", "(position ^ sign) >"),
            "position-unsigned": ("const uint64_t sign = UINT64_C(1) << 63;", "const uint64_t sign = 0;"),
            "relative-carry": ("offset += pair(handle + 1);", "offset = (uint32_t)(offset + pair(handle + 1));"),
            "origin-error": ("0xE0E046BD", "0xE0E046C1"),
            "size-output-failure": ("if (!(result >> 31))\n        *size = value;", "*size = (result >> 31) ? 0 : value;"),
        })
        edits.update({
            "loop-sign": ("(0u - (received >> 31)) + (handle[1] < low)", "(handle[1] < low)"),
            "loop-count-failure": ("return result; /* Keep prior progress, but do not publish count. */", "{ *count = total; return result; }"),
            "loop-buffer": ("buffer += received;", "buffer += 1;"),
            "loop-remaining": ("bytes -= received;", "bytes -= 1;"),
            "loop-positive": ("if (result >> 31)", "if (result != 0)"),
            "loop-zero": ("received == bytes || received == 0", "received == bytes"),
        })
        edits.update({
            "prefix-sign": ("0u - (byte >> 7)", "0u"),
            "prefix-limit": ("i < 8", "i < 9"),
            "prefix-last": ("entry < 32", "entry < 31"),
            "open-length": ("+ 1u) * 2u", "+ 0u) * 2u"),
            "open-status": ("if (!(result >> 31))", "if (result == 0)"),
            "open-preserve": ("if (!(result >> 31))", "if (1)"),
        })
        edits.update({
            "cleanup-reload": ("if (object[1] & 1)\n            smt4_worker_file_preclose(object[1], 0, payload);\n        smt4_worker_file_close(object[1] & ~UINT32_C(1));", "uint32_t saved = object[1];\n        if (saved & 1) smt4_worker_file_preclose(saved, 0, payload);\n        smt4_worker_file_close(saved & ~UINT32_C(1));"),
            "cleanup-tag-only": ("if (object[1] & ~UINT32_C(1))", "if (object[1] != 0)"),
            "cleanup-clear": ("object[1] = 0;", "object[1] = 1;"),
            "cleanup-return": ("return object;", "return object + 1;"),
            "close-slot": ("vtable[0x2c / 4]", "vtable[0x28 / 4]"),
            "release-null": ("if (object != 0)", "if (1)"),
        })
        edits.update({
            "path-initial": ("state[0] == 0", "state[1] == 0"),
            "path-limit": ("while (limit != 0)", "while (1)"),
            "path-error": ("*smt4_worker_path_error() = 4;", "*smt4_worker_path_error() = 5;"),
            "path-slot": ("state_slot(0, 4)", "state_slot(0, 5)"),
            "path-result": ("return unit == 0 ? 0 : consumed;", "return unit == 0 ? 0 : result;"),
            "path-mode": ("locale[0x101] == 1", "locale[0x101] != 0"),
        })
        edits.update({
            "locale-gap": ("index < 0x582", "index < 0x583"),
            "locale-trail": ("byte - 0x40u >= 0x3fu", "byte - 0x40u >= 0x40u"),
            "locale-reset": ("state[0] = 0;", "state[0] = lead;"),
            "locale-yen": ("byte = 0xa5;", "byte = 0x5c;"),
        })
        edits.update({
            "bootstrap-offset": ("context[3] =", "context[2] ="),
            "bootstrap-empty": ("name != 0 && *name != 0 &&\n        smt4_worker_locale_name_compare(smt4_worker_locale_byte_name", "name != 0 &&\n        smt4_worker_locale_name_compare(smt4_worker_locale_byte_name"),
            "bootstrap-compare": ("(difference >> 1)", "(difference >> 2)"),
        })
        edits.update({
            "config-mask": ("mask >= 32u", "mask > 32u"),
            "config-byte": ("byte < 0x3au", "byte < 0x3bu"),
            "config-order": ("if (mask & 4u) {", "if ((mask & 4u) && !(mask & 8u)) {"),
        })
        edits.update({
            "registry-vacancy": ("if (record[2] == 0)", "if (record[2] == 0 && record[0] != (uint32_t)key)"),
            "registry-sign": ("0u - (byte >> 7)", "0u"),
            "registry-reload": ("((void (*)(uint32_t))(uintptr_t)vtable[0x30 / 4])(backend);\n            if (smt4_worker_backend_state[2] == backend)", "uint32_t cached = smt4_worker_backend_state[2];\n            ((void (*)(uint32_t))(uintptr_t)vtable[0x30 / 4])(backend);\n            if (cached == backend)"),
        })
        edits.update({
            "break-clear": ("smt4_break_callback_slot = 0;", "smt4_break_callback_slot = callback;"),
            "break-payload": ("callback(reason, 0, 0, 0, 0, payload);", "callback(reason, 0, 0, 0, 0, payload ^ 1u);"),
            "break-reason": ("smt4_break_dispatch(0, 0, payload)", "smt4_break_dispatch(unused0, 0, payload)"),
            "break-svc": ("smt4_break_svc(reason, 0, 0)", "smt4_break_svc(reason, 0, 1)"),
            "break-prefix-payload": ("removing ? 8u :", "removing ? 7u :"),
        })
        edits.update({
            "init-count": ("while (count != 0)", "while (count > 1)"),
            "init-stride": ("cursor += stride;", "cursor += stride | 16u;"),
            "init-base": ("return base;", "return base + stride;"),
            "init-tail": ("record[2] = 0;", "record[2] = 0; record[3] = 0;"),
            "init-startup-count": ("initialize, 16, 32)", "initialize, 16, 31)"),
        })
        old, new = edits[args.mutant]
        if allocation_mutant:
            source = allocation_sources[1 if args.mutant == "data-backlink" else 0]
        if method_mutant:
            source = method_sources[0]
        if position_mutant:
            source = position_sources[0]
        if read_mutant:
            source = read_sources[0]
        if open_mutant:
            source = open_sources[0]
        if cleanup_mutant:
            source = cleanup_sources[0]
        if path_mutant:
            source = path_sources[0]
        if locale_mutant:
            source = locale_sources[0]
        if bootstrap_mutant:
            source = bootstrap_sources[0]
        if config_mutant:
            source = config_sources[0]
        if prefix_mutant:
            source = prefix_sources[0]
        elif break_mutant:
            source = break_sources[0]
        if initialize_mutant:
            source = initialize_sources[1 if args.mutant in ("init-tail", "init-startup-count") else 0]
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "mutant.c"
        source.write_text(text.replace(old, new))
        if allocation_mutant:
            allocation_sources[1 if args.mutant == "data-backlink" else 0] = source
            source = ROOT / "src/resource_worker_io.c"
        if method_mutant:
            method_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if position_mutant:
            position_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if read_mutant:
            read_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if open_mutant:
            open_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if cleanup_mutant:
            cleanup_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if path_mutant:
            path_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if locale_mutant:
            locale_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if bootstrap_mutant:
            bootstrap_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if config_mutant:
            config_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if prefix_mutant:
            prefix_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        elif break_mutant:
            break_sources[0] = source
            source = ROOT / "src/resource_worker_io.c"
        if initialize_mutant:
            initialize_sources[1 if args.mutant in ("init-tail", "init-startup-count") else 0] = source
            source = ROOT / "src/resource_worker_io.c"
    elf, binary = output / "resource-worker-io.elf", output / "resource-worker-io.bin"
    definitions = {
        "smt4_worker_file_construction": 0x420870,
        "smt4_worker_io_lock_handle": 0x465124,
        "smt4_worker_io_busy": 0x465004,
        "smt4_worker_object_allocate": 0x2c244c,
        # Synthetic ARM call boundaries for the original Thumb helpers.
        "smt4_worker_path_is_initial": 0x710000,
        "smt4_worker_path_measure": 0x710004,
        "smt4_worker_path_convert": 0x710008,
        "smt4_worker_file_open": 0x2bb944,
        "smt4_worker_data_allocate": 0x2bf7ec,
        "smt4_worker_io_acquire": 0x2c3afc,
        "smt4_worker_io_release": 0x2c3a78,
        "smt4_worker_file_preclose": 0x2bce9c,
        "smt4_worker_file_close": 0x2b9450,
    }
    if args.recover_allocation:
        del definitions["smt4_worker_object_allocate"]
        del definitions["smt4_worker_data_allocate"]
        definitions.update({"smt4_resource_allocator_state": 0x465120,
                            "smt4_resource_heap_acquire": 0x2c3afc,
                            "smt4_resource_heap_release": 0x2c3a78,
                            "smt4_resource_allocate_raw": 0x2b26f0,
                            "smt4_resource_allocate_register": 0x2b260c,
                            "smt4_resource_allocate_zero": 0x2c3b9c})
    if args.recover_clear:
        del definitions["smt4_resource_allocate_zero"]
        allocation_sources.append(ROOT / "src/resource_clear.c")
    if args.recover_file_methods:
        definitions.update({"smt4_worker_file_size_lower": 0x2bb8ec,
                            "smt4_worker_file_seek_lower": 0x2aca78,
                            "smt4_worker_file_read_lower": 0x2bb864,
                            "smt4_worker_file_diagnostic": 0x2bbd70})
    if args.recover_file_position:
        del definitions["smt4_worker_file_size_lower"]
        del definitions["smt4_worker_file_seek_lower"]
        definitions["smt4_worker_file_size_service"] = 0x2a8914
    if args.recover_file_read:
        del definitions["smt4_worker_file_read_lower"]
        definitions["smt4_worker_file_read_service"] = 0x2a4e54
    if args.recover_file_open:
        del definitions["smt4_worker_file_open"]
        definitions["smt4_worker_prefix_table"] = 0x4d43e0
    if args.recover_file_cleanup:
        del definitions["smt4_worker_file_close"]
        definitions["smt4_resource_release"] = 0x2c43b4
    if args.recover_path:
        for name in ("smt4_worker_path_is_initial", "smt4_worker_path_measure", "smt4_worker_path_convert"):
            del definitions[name]
        definitions.update({"smt4_worker_locale_storage": 0x4efca0,
                            "smt4_worker_path_states": 0x4efce4,
                            "smt4_worker_path_error_storage": 0x4efce0})
    if args.recover_locale:
        definitions["smt4_worker_locale_mapping"] = 0x41caa0
    if args.recover_locale_bootstrap:
        definitions.update({"smt4_worker_locale_byte_name": 0x42a040,
                            "smt4_worker_locale_other_name": 0x42a160,
                            "smt4_worker_locale_byte_table": 0x42a04c,
                            "smt4_worker_locale_other_table": 0x42a168})
    if args.recover_locale_config:
        definitions.update({"smt4_worker_locale_default_name": 0x2c6c40, "smt4_worker_locale_fixed_table": 0x42a184})
    if args.recover_prefix:
        definitions.update({"smt4_worker_backend_state": 0x44e650, "smt4_worker_prefix_fallback": 0x407fbc, "smt4_worker_prefix_diagnostic": 0x2bce9c})
    if args.recover_break:
        del definitions["smt4_worker_file_preclose"]
        del definitions["smt4_worker_prefix_diagnostic"]
        definitions["smt4_break_callback_slot"] = 0x44e450
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), *map(str, allocation_sources + method_sources + position_sources + read_sources + open_sources + cleanup_sources + path_sources + locale_sources + bootstrap_sources + config_sources + prefix_sources + break_sources + initialize_sources), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_state0_io", "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in definitions.items()],
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         *(["--only-section=.rodata"] if args.recover_locale_config else []),
         str(elf), str(binary)], output, "objcopy")
    if args.recover_locale_config:
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x113e80", "--stop-address=0x114134",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    if args.recover_clear:
        (output / "clear-entry.txt").write_text(str(entries["smt4_resource_allocate_zero"]))
    (output / "entries.txt").write_text(f"{entries['smt4_worker_state0_io']}\n")
    if args.recover_allocation:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_object_allocate", "smt4_worker_data_allocate", "smt4_resource_allocate_lower"):
                stream.write(f"{entries[name]}\n")
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", "--start-address=0x2c244c", "--stop-address=0x2c2484",
             str(code)], output, "original-object-disassembly")
    if args.recover_file_methods:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_file_size", "smt4_worker_file_seek", "smt4_worker_file_read"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop in (("size", 0x3dfc54, 0x3dfc80), ("seek-read", 0x354f70, 0x354fa4)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
                 "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}",
                 str(code)], output, "original-" + label + "-disassembly")
    if args.recover_file_position:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_file_size_lower", "smt4_worker_file_seek_lower", "smt4_worker_file_position"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop in (("size-cache", 0x2bb8ec, 0x2bb944), ("seek-origin", 0x2aca78, 0x2acb28), ("position", 0x146458, 0x1464f8)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
                 "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}",
                 str(code)], output, "original-" + label + "-disassembly")
    if args.recover_file_read:
        with (output / "entries.txt").open("a") as stream:
            stream.write(f"{entries['smt4_worker_file_read_lower']}\n")
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", "--start-address=0x2bb864", "--stop-address=0x2bb8ec",
             str(code)], output, "original-read-disassembly")
    if args.recover_file_open:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_file_open", "smt4_worker_path_backend", "smt4_worker_utf16_length"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop, thumb in (("open", 0x2bb944, 0x2bb9d8, False), ("prefix", 0x2b5ca0, 0x2b5d6c, False), ("utf16", 0x2b5c8c, 0x2b5c9e, True)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
                 *(["-M", "force-thumb"] if thumb else []), "--adjust-vma=0x100000",
                 f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-" + label + "-disassembly")
    if args.recover_file_cleanup:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_file_cleanup", "smt4_worker_file_cleanup_shared", "smt4_worker_file_destroy", "smt4_worker_file_close", "smt4_worker_object_release"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop in (("cleanup", 0x2bb81c, 0x2bb85c), ("destroy", 0x354fa4, 0x354fb8), ("close", 0x2b9450, 0x2b9468), ("object-release", 0x2b2580, 0x2b2590), ("diagnostic-svc", 0x1526b4, 0x1526bc)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-"+label+"-disassembly")
    if args.recover_path:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_path_is_initial", "smt4_worker_path_measure", "smt4_worker_path_convert", "smt4_worker_path_decode_byte", "smt4_worker_path_state_slot", "smt4_worker_path_error", "smt4_worker_locale_context", "smt4_worker_locale_slot"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop, thumb in (("path-wrappers",0x2b9468,0x2b9498,True),("path-convert",0x2c63dc,0x2c6450,True),("path-decode",0x1008c8,0x100908,True),("path-state",0x2c6936,0x2c6944,True),("path-error",0x2c6894,0x2c68a0,False),("locale-context",0x2c6c48,0x2c6c54,False),("locale-slot",0x2c6c94,0x2c6ca4,False)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", *(["-M", "force-thumb"] if thumb else []), "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-"+label+"-disassembly")
    if args.recover_locale:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_locale_map", "smt4_worker_locale_decode"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop in (("locale-map",0x100f9c,0x100fc8),("locale-callback",0x100fc8,0x101080)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", "-M", "force-thumb", "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-"+label+"-disassembly")
    if args.recover_locale_bootstrap:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_locale_bootstrap", "smt4_worker_locale_select_bytes", "smt4_worker_locale_select_other", "smt4_worker_locale_name_compare"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop in (("bootstrap",0x10236c,0x1023c0),("select-bytes",0x138208,0x138250),("select-other",0x14d908,0x14d950),("name-compare",0x2aa858,0x2aa914)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-"+label+"-disassembly")
    if args.recover_locale_config:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_locale_query", "smt4_worker_locale_configure", "smt4_worker_locale_set_name"):
                stream.write(f"{entries[name]}\n")
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", "-M", "force-thumb", "--adjust-vma=0x100000", "--start-address=0x2c6aa8", "--stop-address=0x2c6c48", str(code)], output, "original-config-disassembly")
    if args.recover_prefix:
        with (output / "entries.txt").open("a") as stream:
            for name in ("smt4_worker_prefix_register", "smt4_worker_prefix_remove"):
                stream.write(f"{entries[name]}\n")
        for label, start, stop in (("register",0x2b5e70,0x2b5fcc),("remove",0x2c4054,0x2c41b4)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-prefix-"+label+"-disassembly")
    if args.recover_break:
        (output / "break-entries.txt").write_text("\n".join(str(entries[n]) for n in ("smt4_worker_file_preclose", "smt4_break_dispatch", "smt4_break_svc")) + "\n")
        for label, start, stop in (("break-zero",0x2bce9c,0x2bcea4),("break-dispatch",0x2ad90c,0x2ad95c),("break-svc",0x1526b4,0x1526bc)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-"+label+"-disassembly")
    if args.recover_registry_initialize:
        (output / "registry-initialize-entries.txt").write_text("\n".join(str(entries[n]) for n in ("smt4_array_initialize", "smt4_worker_prefix_record_initialize", "smt4_worker_prefix_initialize")) + "\n")
        for label, start, stop, thumb in (("array-initialize",0x2c5fac,0x2c5fce,True),("record-initialize",0x3561f0,0x356204,False),("registry-startup",0x3f3570,0x3f3584,False)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm", *(["-M", "force-thumb"] if thumb else []), "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(code)], output, "original-"+label+"-disassembly")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceRegistryInitialize.java" if args.recover_registry_initialize else "CompareResourceBreak.java" if args.recover_break else "CompareResourceWorkerPrefix.java" if args.recover_prefix else "CompareResourceWorkerLocaleConfig.java" if args.recover_locale_config else "CompareResourceWorkerLocaleBootstrap.java" if args.recover_locale_bootstrap else "CompareResourceWorkerLocale.java" if args.recover_locale else "CompareResourceWorkerPath.java" if args.recover_path else "CompareResourceWorkerFileCleanup.java" if args.recover_file_cleanup else "CompareResourceWorkerFileOpen.java" if args.recover_file_open else "CompareResourceWorkerFileRead.java" if args.recover_file_read else "CompareResourceWorkerFilePosition.java" if args.recover_file_position else "CompareResourceWorkerFileMethods.java" if args.recover_file_methods else "CompareResourceWorkerAllocation.java" if args.recover_allocation else "CompareResourceWorkerIo.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_WORKER_IO_COMPARE_OK" in log:
            raise RuntimeError("Mutant survived")
        if "Worker I/O case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Failure was not an asserted corpus rejection")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(output / "mutant.c"),
                  "binary_sha256": digest(binary), "recover_allocation": args.recover_allocation,
                  "recover_file_methods": args.recover_file_methods}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_WORKER_IO_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["io_cases"] != (2304 if args.recover_allocation else 3456) or (not args.recover_allocation and comparison["original_instruction_addresses"] != 163):
        raise RuntimeError("Incomplete comparison corpus")
    if args.recover_allocation and (comparison["direct_object_cases"] != 48 or comparison["executed_allocations_both_paths"] != 6912 or comparison["original_instruction_addresses"] != (556 + comparison["new_path_instruction_addresses"] + comparison.get("new_locale_instruction_addresses", 0) + comparison.get("new_bootstrap_instruction_addresses", 0) + comparison.get("new_config_instruction_addresses", 0) + comparison.get("new_registry_instruction_addresses", 0) if args.recover_path else 556 if args.recover_file_cleanup else 525 if args.recover_file_open else 431 if args.recover_file_read else 397 if args.recover_file_position else 293 if args.recover_file_methods else 269) + (30 if args.recover_clear else 0) + (23 if args.recover_break else 0)):
        raise RuntimeError("Incomplete allocation corpus")
    if args.recover_clear and (comparison.get("executed_clear_calls_both") != 6912 or not comparison.get("clearing_recovered")):
        raise RuntimeError("Incomplete recovered clear corpus")
    if args.recover_file_methods and (comparison["direct_method_cases"] != 210 or comparison["terminal_size_failures_both_paths"] != 24):
        raise RuntimeError("Incomplete method corpus")
    if args.recover_file_position and (comparison["direct_position_cases"] != 3312 or comparison["persistent_position_sequences"] != 4 or comparison["new_position_instruction_addresses"] != 104 or comparison["connected_position_calls_both_paths"] != 9216 or not comparison["size_seek_position_recovered"]):
        raise RuntimeError("Incomplete position corpus")
    if args.recover_file_read and (comparison["direct_read_cases"] != 724 or comparison["persistent_read_sequences"] != 2 or comparison["new_read_instruction_addresses"] != 34 or comparison["connected_read_calls_both_paths"] != 4608 or not comparison["read_loop_recovered"]):
        raise RuntimeError("Incomplete read corpus")
    if args.recover_file_open and (comparison["new_open_instruction_addresses"] != 94 or comparison["connected_open_calls_both_paths"] != 4608 or not comparison["open_prefix_length_recovered"]):
        raise RuntimeError("Incomplete open corpus")
    if args.recover_file_cleanup and (comparison["direct_cleanup_cases"] != 68 or comparison["new_cleanup_instruction_addresses"] != 31 or not comparison["cleanup_destructor_close_recovered"]):
        raise RuntimeError("Incomplete cleanup corpus")
    if args.recover_path and (not comparison["path_conversion_recovered"] or comparison["connected_path_calls_both"] == 0):
        raise RuntimeError("Incomplete path corpus")
    if args.recover_locale and (not comparison["default_locale_callback_recovered"] or comparison["connected_locale_calls_both"] == 0):
        raise RuntimeError("Incomplete locale corpus")
    if args.recover_locale_bootstrap and (not comparison["connected_bootstrap_executed"] or comparison["connected_bootstrap_calls_both"] != 4608):
        raise RuntimeError("Incomplete bootstrap corpus")
    if args.recover_locale_config and (not comparison["locale_configuration_recovered"] or comparison["connected_configuration_calls_both"] != 4608):
        raise RuntimeError("Incomplete configuration corpus")
    if args.recover_prefix and (not comparison["prefix_mutation_recovered"] or comparison["connected_registrations_both"] != 4608):
        raise RuntimeError("Incomplete prefix corpus")
    if args.recover_break and (comparison["direct_break_pairs"] != 72 or comparison["new_break_instruction_sites"] != 23 or not comparison["break_dispatch_recovered"]):
        raise RuntimeError("Incomplete break corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Adapted state-zero region; lower file/path/allocation/locking modeled; successful object allocation",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker_io.c", "src/resource_worker_io.h", "src/resource_worker_path.h",
                    "tools/check_resource_worker_io.py", "tools/ghidra/CompareResourceWorkerIo.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java",
                    "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    if args.recover_allocation:
        manifest["method"] = "Adapted worker I/O with executed object/lower/data allocators and retained guarded metadata; raw storage, registration, zero, locks and lower file/path services modeled"
        for name in ("src/resource_worker_object_allocate.c", "src/resource_worker_data_allocate.c", "src/resource_allocate_lower.c", "src/resource_allocate.h", "tools/ghidra/CompareResourceWorkerAllocation.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_file_methods:
        manifest["method"] += "; executed size/seek/read adapters; size failure stops at modeled diagnostic; seek diagnostic modeled returning"
        for name in ("src/resource_worker_file_methods.c", "src/resource_worker_file_methods.h", "tools/ghidra/CompareResourceWorkerFileMethods.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_file_position:
        manifest["method"] += "; connected lower size/cache, seek dispatch and position executed; OS size service, read and diagnostics modeled; separate old direct adapter probes retain lower models"
        for name in ("src/resource_worker_file_position.c", "tools/ghidra/CompareResourceWorkerFilePosition.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_file_read:
        manifest["method"] += "; connected/direct read loop executed with scripted OS read; earlier isolated adapter probes retain lower models"
        for name in ("src/resource_worker_file_read.c", "tools/ghidra/CompareResourceWorkerFileRead.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_file_open:
        manifest["method"] += "; connected/direct prefix/open/UTF-16 length executed; backend virtual open modeled; earlier modes retain open model"
        for name in ("src/resource_worker_file_open.c", "src/resource_worker_file_open.h", "tools/ghidra/CompareResourceWorkerFileOpen.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_file_cleanup:
        manifest["method"] += "; cleanup/destruction/close dispatch executed; backend close and resource release modeled; returning diagnostic continuation conditional, terminal probes stop at diagnostic, original diagnostic chain stops before SVC 0x3C"
        for name in ("src/resource_worker_file_cleanup.c", "src/resource_worker_file_cleanup.h", "tools/ghidra/CompareResourceWorkerFileCleanup.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_path:
        manifest["method"] += "; connected path predicate/measurement/conversion/byte decoder and fixed accessors execute with valid byte tables; direct callback probes model locale callbacks; initialization remains unrecovered"
        for name in ("src/resource_worker_path.c", "src/resource_worker_path.h", "tools/ghidra/CompareResourceWorkerPath.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_locale:
        manifest["method"] += "; connected default locale callback/map execute with hash-bound private data and relocated callback binding; earlier direct path probes retain scripted callbacks; initialization unrecovered"
        for name in ("src/resource_worker_locale.c", "src/resource_worker_locale.h", "tools/ghidra/CompareResourceWorkerLocale.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_locale_bootstrap:
        manifest["method"] = manifest["method"].replace("initialization remains unrecovered", "older direct probes use fixture initialization").replace("initialization unrecovered", "older direct probes use fixture initialization")
        manifest["method"] += "; connected bootstrap/selectors execute before conversion; name comparison recovered; inherited direct locale probes retain fixture initialization"
        for name in ("src/resource_worker_locale_bootstrap.c", "src/resource_worker_locale_bootstrap.h", "tools/ghidra/CompareResourceWorkerLocaleBootstrap.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_locale_config:
        manifest["method"] += "; connected category configuration executes after bootstrap; guarded direct query/name/restore probes execute with private relative-name data"
        for name in ("src/resource_worker_locale_config.c", "src/resource_worker_locale_config.h", "tools/ghidra/CompareResourceWorkerLocaleConfig.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_prefix:
        manifest["method"] += "; prefix registration/removal executed; connected registration replaces populated-table fixture, zero/occupied initial storage remains synthetic; disposal and diagnostic modeled"
        for name in ("src/resource_worker_prefix.c", "src/resource_worker_prefix.h", "tools/ghidra/CompareResourceWorkerPrefix.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_clear:
        manifest["method"] += "; recovered clearing replaces zero model and its callback effects"
        for name in ("src/resource_clear.c", "src/resource_clear.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    # These headers are transitively consumed even in modes retaining the model.
    manifest["files_sha256"]["src/resource_break.h"] = digest(ROOT / "src/resource_break.h")
    if args.recover_break:
        manifest["method"] += "; break mode supersedes the inherited preclose/prefix diagnostic models: callback dispatch and SVC wrapper execute; only callback body and kernel effects modeled; terminal paths stop at SVC"
        for name in ("src/resource_break.c", "tools/ghidra/CompareResourceBreak.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["break_dispatch"] = {"new_contracts": 3, "active_original_call_models_removed": 1,
                                      "shared_model_names": ["smt4_worker_file_preclose", "smt4_worker_prefix_diagnostic"],
                                      "raw_r2_caller_transport_extended": True, "callback_and_svc_modeled": True}
        caller_checks = json.loads((output / "break-caller-summary.json").read_text())
        if caller_checks != {"cleanup_payload_pairs": 9, "prefix_payload_pairs": 12, "persistent_sequences_both": 2}:
            raise RuntimeError("Incomplete break caller boundaries")
        manifest["break_dispatch"]["caller_checks"] = caller_checks
    if args.recover_registry_initialize:
        if not comparison.get("registry_initialization_recovered") or comparison["direct_initializer_pairs"] != 57 or comparison["initialized_lifecycle_sequences_both"] != 4 or comparison["connected_initializations_both"] != 4608 or comparison["new_initializer_instruction_sites"] != 27:
            raise RuntimeError("Incomplete registry initialization corpus")
        manifest["method"] += "; initialization mode replaces zero key/backend fixtures in new persistent and connected worker sequences with recovered startup/array/record code; inherited direct registry probes retain arbitrary fixtures; arbitrary constructors and backend services remain modeled"
        for name in ("src/resource_array_initialize.c", "src/resource_array_initialize.h", "src/resource_worker_prefix_initialize.c", "tools/ghidra/CompareResourceRegistryInitialize.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["registry_initialization"] = {"new_complete_routines": 2, "adapted_startup_slices": 1, "connected_initial_key_backend_fixture_removed": True, "broader_startup_recovered": False}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
