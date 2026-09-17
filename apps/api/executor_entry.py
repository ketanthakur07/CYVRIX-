"""Sandbox entrypoint: probes (evidence) → executor → bounded result.

Runs INSIDE the sandbox as uid 10001 with python -I (isolated mode).
Never executes repository content; repository files are data.
"""
import json
import os
import sys

sys.path.insert(0, "/opt/cyvrix")

PAYLOAD_DIR = "/workspace/.cyvrix"


def main() -> int:
    os.makedirs(PAYLOAD_DIR, exist_ok=True)

    # 1. Isolation self-probes (harmless PoCs; host asserts the results)
    try:
        from cyvrix_executor import probes
        results = probes.run_probes()
        with open(os.path.join(PAYLOAD_DIR, "probes.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    except Exception:
        # Probe failure must not block the run; host treats missing
        # probes.json as evidence-unavailable.
        pass

    # 2. Closed-world executor
    from cyvrix_executor.executor import main as executor_main
    return executor_main()


if __name__ == "__main__":
    sys.exit(main())
