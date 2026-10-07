"""Create a fresh local Ghidra project for the pinned EU executable, or open it."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODE_HASH = "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"
EXHEADER_HASH = "27305333aae9ce837964861a589ee3e44bb7ae234041d31bf97a20bba79cf29e"


def local_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    if not path.is_relative_to((ROOT / "local").resolve()) or path == ROOT / "local":
        raise ValueError("Project/output must be inside repository local/")
    return path


def check_hash(path: Path, expected: str) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch: {path}")


def java_command(gui: bool = False) -> list[str]:
    pin = json.loads((ROOT / "config/analysis-tools.json").read_text())
    ghidra = ROOT / pin["ghidra"]["directory"]
    jdk = ROOT / pin["jdk"]["directory"]
    java = jdk / "bin" / ("javaw.exe" if gui else "java.exe")
    utility = ghidra / "Ghidra/Framework/Utility/lib/Utility.jar"
    for path in (java, utility):
        if not path.is_file():
            raise FileNotFoundError(f"Missing pinned tool: {path}")
    check_hash(java, pin["jdk"]["javaw_exe_sha256" if gui else "java_exe_sha256"])
    check_hash(utility, pin["ghidra"]["utility_jar_sha256"])
    # Use release launch.properties defaults, then confine settings/caches locally.
    options = []
    for line in (ghidra / "support/launch.properties").read_text().splitlines():
        if line.startswith(("VMARGS=", "VMARGS_WINDOWS=")):
            option = line.split("=", 1)[1]
            if option and not option.endswith("="):
                options.append(option)
    state = ROOT / "local/ghidra-state"
    for name in ("settings", "cache", "temp"):
        (state / name).mkdir(parents=True, exist_ok=True)
        prop = {"settings": "settingsdir", "cache": "cachedir", "temp": "tempdir"}[name]
        options.append(f"-Dapplication.{prop}={state / name}")
    return [str(java), "-Xmx2G", *options, "-cp", str(utility), "ghidra.Ghidra"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--open", action="store_true", help="Open the existing project in Ghidra")
    args = parser.parse_args()
    project = local_path(args.project_dir)
    name = "SMT4-EU"
    if args.open:
        gpr = project / f"{name}.gpr"
        if not gpr.is_file():
            raise FileNotFoundError(gpr)
        command = [*java_command(True), "ghidra.GhidraRun", str(gpr)]
        with (ROOT / "local/ghidra-state/gui-console.log").open("a", encoding="utf-8") as log:
            process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        print(f"Launched Ghidra (PID {process.pid}) for {gpr}")
        return
    if project.exists():
        raise FileExistsError(f"Refusing to overwrite {project}; choose a fresh --project-dir")
    reference = ROOT / "local/reference-eu/base/0000"
    code = reference / "exefs/code.bin"
    for path, expected in ((code, CODE_HASH), (reference / "exheader.bin", EXHEADER_HASH)):
        check_hash(path, expected)
    command = java_command()
    project.mkdir(parents=True)
    output = project / "exports"
    command += ["ghidra.app.util.headless.AnalyzeHeadless", str(project), name,
                "-import", str(code), "-loader", "BinaryLoader",
                "-processor", "ARM:LE:32:v6", "-cspec", "default",
                "-loader-baseAddr", "0x00100000", "-scriptPath", str(ROOT / "tools/ghidra"),
                "-preScript", "ImportSmt4.java", str(code),
                "-postScript", "ExportSmt4.java", str(output),
                "-analysisTimeoutPerFile", "600", "-max-cpu", "4",
                "-log", str(project / "analysis.log"),
                "-scriptlog", str(project / "scripts.log")]
    (project / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (project / "console.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    log_text = (project / "console.log").read_text(encoding="utf-8", errors="replace")
    if result.returncode or not (output / "COMPLETE.txt").is_file() or "SMT4_MAP_OK" not in log_text:
        raise RuntimeError(f"Import/analysis failed; inspect {project / 'console.log'}")
    if ("REPORT: Analysis succeeded for file:" not in log_text or
            "REPORT: Save succeeded" not in log_text or
            "REPORT: Import succeeded" not in log_text or
            "analysis timed out" in log_text.lower()):
        raise RuntimeError("Analysis/import/save did not complete cleanly; inspect console.log")
    print((output / "COMPLETE.txt").read_text(), end="")
    print(f"Project: {project / (name + '.gpr')}")


if __name__ == "__main__":
    main()
