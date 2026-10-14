"""Shared build support for the constructor's optional concrete synchronization."""
import json
from ghidra_reference import ROOT
from check_nkm_lookup import digest

NAMES = ("smt4_file_acquire", "smt4_file_release", "smt4_file_check_result")
MUTANTS = ("sync-publication", "sync-timeout", "sync-payload")
DIAGNOSTIC_MUTANTS = ("diagnostic-order", "diagnostic-type", "diagnostic-tail", "delivery-release-r2", "delivery-wait-r2")


def build_args(output, enabled, mutant, diagnostic=False):
    if not enabled:
        return [f"-Wl,--defsym,{name}={address}" for name, address in
                zip(NAMES, ("0x2c4350", "0x2c54a4", "0x2c54bc"))]
    source = ROOT / "src/resource_create_sync.c"
    if mutant in MUTANTS:
        text = source.read_text()
        old, new = {
            "sync-publication": ("*index = (uint32_t)(uintptr_t)r1;",
                                 "if (!(r0 >> 31)) *index = (uint32_t)(uintptr_t)r1;"),
            "sync-timeout": ("(uint32_t)(timeout >> 32)", "(uint32_t)timeout"),
            "sync-payload": ("payload = (uint32_t)(words >> 32);", "payload = 0;"),
        }[mutant]
        if text.count(old) != 1:
            raise RuntimeError("Sync mutant anchor changed")
        source = output / "mutant-sync.c"
        source.write_text(text.replace(old, new))
    diagnostic_args = ["-Wl,--defsym,smt4_file_result_diagnostic=0x1284a8"]
    if diagnostic:
        producer = ROOT / "src/resource_result_diagnostic.c"
        if mutant in DIAGNOSTIC_MUTANTS[:3]:
            text = producer.read_text()
            old, new = {
                "diagnostic-order": ("smt4_diagnostic_global.flags = 0;\n    smt4_diagnostic_global.type = (uint8_t)type;",
                                     "smt4_diagnostic_global.type = (uint8_t)type;\n    smt4_diagnostic_global.flags = 0;"),
                "diagnostic-type": ("smt4_diagnostic_global.type = (uint8_t)type;", "smt4_diagnostic_global.type = (uint8_t)(type >> 8);"),
                "diagnostic-tail": ('"b smt4_diagnostic_deliver\\n"',
                                    '"push {r4, lr}\\n"\n    "bl smt4_diagnostic_deliver\\n"\n    "mov r2, #0\\n"\n    "pop {r4, pc}\\n"'),
            }[mutant]
            if text.count(old) != 1:
                raise RuntimeError("Diagnostic mutant anchor changed")
            producer = output / "mutant-result-diagnostic.c"
            producer.write_text(text.replace(old, new))
        diagnostic_args = [str(producer), "-Wl,--defsym,smt4_diagnostic_global=0x4d4200",
                           *delivery_args(output, mutant)]
    return [str(source), "-I" + str(ROOT / "src"),
            "-Wl,--defsym,smt4_file_result_kernel_flag=0x1ff80014",
            "-Wl,--defsym,smt4_file_result_debug_flag=0x44e7a8",
            *diagnostic_args,
            "-Wl,--defsym,smt4_file_result_break=0x2bce9c"]


def save_entries(output, entries, diagnostic=False):
    (output / "sync-entries.txt").write_text("".join(f"{entries[name]}\n" for name in NAMES))
    if diagnostic:
        (output / "wait-entries.txt").write_text(f'{entries["smt4_diagnostic_wait_initialize"]}\n{entries["smt4_diagnostic_wait"]}\n')
        (output / "delivery-entry.txt").write_text(f'{entries["smt4_diagnostic_deliver"]}\n')
        (output / "result-diagnostic-entry.txt").write_text(f'{entries["smt4_file_result_diagnostic"]}\n')


def manifest_evidence(output, manifest, direct, diagnostic=False):
    evidence = json.loads((output / "sync-comparison.json").read_text())
    if (evidence["direct_pairs"] != (1168 if direct else 0)
            or evidence["original_sync_sites"] != (41 if direct else 40)
            or not all(evidence[k] for k in ("svc_marshalling_checked", "failure_publication_checked",
                                             "caller_r2_transport_checked", "flag_read_order_checked"))):
        raise RuntimeError("Missing synchronization evidence")
    manifest["synchronization"] = evidence
    manifest["synchronization_recovered"] = True
    manifest["new_contracts"] = ["0x002C4350", "0x002C54A4", "0x002C54BC"]
    manifest["remaining_sync_models"] = ["SVC 0x25 outcomes", "SVC 0x16 outcomes",
                                          "0x001284A8 diagnostic", "0x002BCE9C returning break"]
    manifest["method"] = ("Original/rebuilt ARM execution of constructor synchronization/result dispatch; "
                          "kernel outcomes, diagnostic delivery, break policy, allocation, clear and formatting modeled; "
                          "string and chain timing boundaries follow the selected mode")
    for name in ("src/resource_create_sync.c", "tools/resource_create_sync_build.py",
                 "tools/ghidra/ResourceCreateSync.java"):
        manifest["files_sha256"][name] = digest(ROOT / name)
    if diagnostic:
        producer = json.loads((output / "result-diagnostic-comparison.json").read_text())
        if (producer["direct_pairs"] != (120 if direct else 0) or producer["original_sites"] != 12
                or not all(producer[k] for k in ("record_store_order_widths_checked", "type_narrowing_checked",
                    "unknown_bytes_guards_checked", "tail_lr_sp_checked", "delivery_r0_r2_transport_checked"))):
            raise RuntimeError("Missing result diagnostic evidence")
        manifest["result_diagnostic"] = producer
        manifest["new_contracts"] = []
        manifest["extended_contracts"] = ["0x002C367C r0/r2 return", "0x002A88FC r2 return"]
        manifest["delivery_return"] = json.loads((output / "delivery-comparison.json").read_text())
        manifest["wait_return_connected"] = json.loads((output / "wait-return-connected.json").read_text())
        manifest["reused_sync_contracts"] = ["0x002C4350", "0x002C54A4", "0x002C54BC"]
        manifest["remaining_sync_models"][2] = "release 0x002C3A78 r0/r2 outcomes; acquire; SVC 0x22 outcomes"
        manifest["method"] = ("Original/rebuilt ARM execution through result diagnostic record producer; "
                              "delivery/process/request/copy/connect/delay execute source; wait/initializer/base initializer/arbitration execute source; lower locks, SVC outcomes, break, allocation, clear and formatting modeled; "
                              "strings and chain timing follow selected mode")
        for name in ("src/resource_result_diagnostic.c", "src/resource_worker_diagnostic.h",
                     "src/resource_aligned_copy.h", "tools/ghidra/ResourceResultDiagnostic.java",
                     "src/resource_worker_diagnostic.c", "src/resource_aligned_copy.c",
                     "src/resource_diagnostic_wait.c", "src/resource_pool_initialize.c", "src/resource_pool_initialize.h",
                     "src/resource_arbitration.c", "src/resource_signal.h",
                     "src/resource_worker_service_setup.c", "src/resource_worker_service_setup.h",
                     "src/resource_wait.c", "src/resource_wait.h", "tools/ghidra/ResourceDiagnosticDelivery.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)


def delivery_args(output, mutant):
    source = ROOT / "src/resource_worker_diagnostic.c"
    if mutant in DIAGNOSTIC_MUTANTS[3:]:
        text = source.read_text()
        old, new = {
            "delivery-release-r2": ("(released & UINT64_C(0xFFFFFFFF00000000)) | type", "(released & UINT64_C(0x00000000FFFFFFFF)) | type"),
            "delivery-wait-r2": ("return smt4_diagnostic_wait_words(state);", "return (uint32_t)smt4_diagnostic_wait_words(state);"),
        }[mutant]
        assert text.count(old) == 1
        source = output / "mutant-delivery.c"
        source.write_text(text.replace(old, new))
    return ["-march=armv6k", str(source), str(ROOT / "src/resource_aligned_copy.c"),
            str(ROOT / "src/resource_worker_service_setup.c"),
            "-ffunction-sections", "-Wl,--gc-sections",
            "-Wl,--defsym,smt4_diagnostic_handle=0x44e608",
            "-Wl,--defsym,smt4_diagnostic_constants=0x407f9c",
            "-Wl,--defsym,smt4_diagnostic_lock=0x4d4280",
            "-Wl,--defsym,smt4_worker_backend_acquire=0x2c3afc",
            "-Wl,--defsym,smt4_worker_backend_release=0x2c3a78",
            str(ROOT / "src/resource_diagnostic_wait.c"),
            str(ROOT / "src/resource_pool_initialize.c"),
            str(ROOT / "src/resource_arbitration.c"),
            "-Wl,--defsym,smt4_arbitration_handle=0x471b58"]
