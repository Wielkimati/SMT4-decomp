"""Export bounded asynchronous request evidence from the saved EU project, read-only."""
import argparse
from ghidra_reference import ROOT, java_command, local_path
from check_nkm_lookup import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    args = parser.parse_args()
    output = local_path(args.output)
    project = local_path(args.project_dir)
    if output.exists():
        raise FileExistsError("Choose new output under local/")
    if not (project / "SMT4-EU.gpr").is_file():
        raise FileNotFoundError("Saved EU project required")
    java = java_command()
    output.mkdir(parents=True)
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "InspectResourceRequest.java",
               str(output / "exports"), "-log", str(output / "ghidra.log")], output, "inspection")
    if "SMT4_REQUEST_INSPECT_OK" not in log or not (output / "exports/COMPLETE.txt").is_file():
        raise RuntimeError("Inspection failed; see inspection.log")
    print((output / "exports/COMPLETE.txt").read_text())


if __name__ == "__main__":
    main()

