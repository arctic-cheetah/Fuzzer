"""
Utilities for running repository binaries against example inputs.

- show(s): minimal function kept for compatibility with main.py
- run_challenge1_against_examples(...): run binaries/challenge1 against all
  files in example_inputs (default) by piping each file's contents to stdin.

Notes:
- This script assumes you execute it in an environment that can run the
  provided binaries (e.g., WSL/Linux or inside the project Docker image).
- It prints a concise summary per input and returns structured results.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List

# PROGRAM_PATH = (Path(__file__).parent / "formatrix").resolve().__str__()


def show(s: str) -> None:
    print(s)


def run_challenge1_against_examples(
    inputs_dir: Path | str = "example_inputs",
    binary_path: Path | str = "binaries/challenge1",
    timeout_seconds: float = 2.0,
    use_stdin: bool = True,
) -> List[Dict[str, object]]:
    """
    Run the challenge1 binary against all files in inputs_dir.

    Args:
            inputs_dir: Directory containing input files (default: example_inputs).
            binary_path: Path to the challenge1 executable (default: binaries/challenge1).
            timeout_seconds: Per-run timeout to avoid hangs.
            use_stdin: If True, pipe file bytes to stdin; otherwise pass file path as arg.

    Preconditions:
        - inputs_dir exists and is readable.
        - binary_path exists and is executable.

    Returns:
            A list of dicts summarizing each run: input_file, exit_code, signal,
            timed_out, stdout, stderr, crashed.
    """

    inputs_dir = Path(inputs_dir)
    binary_path = Path(binary_path)
    results: List[Dict[str, object]] = []

    input_files = sorted(p for p in inputs_dir.iterdir() if p.is_file())
    if not input_files:
        print(f"[warn] no files found in {inputs_dir}")
        return results

    print(
        f"Running {binary_path} against {len(input_files)} input(s) from {inputs_dir}..."
    )

    # For eac input file, run the binary and capture the result
    for inp in input_files:
        # Only consider small to medium files; still, we stream via subprocess input
        data: bytes = b""
        try:
            data = inp.read_bytes()
        except Exception as e:
            print(f"[skip] could not read {inp}: {e}")
            continue

        args = [str(binary_path)]

        try:
            proc = subprocess.run(
                args,
                input=data if use_stdin else None,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
            # Get the return code from the process,
            rc = proc.returncode
            # On POSIX, negative rc indicates termination by signal (-SIGSEGV, etc.)
            signal = -rc if rc < 0 else None
            crashed = rc < 0

            # Truncate outputs for display and make it
            # look pretty
            def trunc(b: bytes, limit: int = 120) -> str:
                s = b.decode(errors="replace")
                return s if len(s) <= limit else s[:limit] + "…"

            result = {
                "input_file": str(inp),
                "exit_code": rc,
                "signal": signal,
                "timed_out": False,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "crashed": crashed,
            }
            results.append(result)

            status = "CRASH" if crashed else ("OK" if rc == 0 else f"RC={rc}")
            print(
                f"- {inp.name}: {status} | stdout='{trunc(proc.stdout)}' | stderr='{trunc(proc.stderr)}'"
            )
        # Store results for the harness
        except subprocess.TimeoutExpired as e:
            results.append(
                {
                    "input_file": str(inp),
                    "exit_code": None,
                    "signal": None,
                    "timed_out": True,
                    "stdout": e.stdout or b"",
                    "stderr": e.stderr or b"",
                    "crashed": False,
                }
            )
            print(f"- {inp.name}: TIMEOUT after {timeout_seconds:.1f}s")
        except Exception as e:  # pylint: disable=broad-except
            print(f"- {inp.name}: ERROR {e}")
            results.append(
                {
                    "input_file": str(inp),
                    "exit_code": None,
                    "signal": None,
                    "timed_out": False,
                    "stdout": b"",
                    "stderr": str(e).encode(),
                    "crashed": False,
                }
            )

    return results


if __name__ == "__main__":
    res = run_challenge1_against_examples(
        inputs_dir="example_inputs", binary_path="binaries/challenge1"
    )
    print(res)
