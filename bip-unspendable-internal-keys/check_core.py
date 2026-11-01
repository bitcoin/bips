#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Optional export cross-check against an isolated, offline Bitcoin Core node.

Requires bitcoind and bitcoin-cli on PATH. Prints a JSON report to stdout.
Never connects to an existing node or reads the user's Bitcoin configuration.
"""

import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from bip32 import VERSIONS
from encoding import base58check_decode, base58check_encode
import reference as ref


def check():
    cases = json.loads((Path(__file__).resolve().parent / "vectors.json").read_text())["valid"]
    selected = {"single", "single-expanded", "four-expansions", "sorted", "sorted-permuted",
                "tree", "tree-swapped", "timelock", "musig"}
    # Release the ephemeral port before Core binds it. A collision fails startup.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="nums-core-") as directory:
        common = ["-regtest", "-datadir=" + directory, "-conf=/dev/null", "-rpcport=" + str(port)]
        with open(Path(directory) / "startup.log", "w+") as log:
            node = subprocess.Popen(["bitcoind", *common, "-nosettings", "-server=1", "-disablewallet=1",
                                     "-listen=0", "-listenonion=0", "-connect=0", "-dnsseed=0",
                                     "-discover=0", "-networkactive=0", "-rpcbind=127.0.0.1"], stdout=log, stderr=log)

            def rpc(method, *args):
                result = subprocess.run(["bitcoin-cli", *common, method, *args],
                                        capture_output=True, text=True, timeout=15)
                if result.returncode:
                    raise RuntimeError(result.stderr.strip())
                return json.loads(result.stdout)

            try:
                for _ in range(100):
                    if node.poll() is not None:
                        log.seek(0)
                        raise RuntimeError("Core startup failed:\n" + log.read())
                    try:
                        info = rpc("getnetworkinfo")
                        break
                    except RuntimeError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Core RPC did not become ready")

                report = {"core_version": info["subversion"], "network": "regtest", "checks": []}
                by_name = {}
                for case in cases:
                    if case["name"] not in selected:
                        continue
                    given = case["given"]
                    policy = ref.normalize_policy(given["template"], given["keys_info"])
                    # Keep the commitment unchanged while exporting network-compatible keys.
                    network_keys = []
                    for key in given["keys_info"]:
                        payload = base58check_decode(key)
                        network_keys.append(base58check_encode(VERSIONS["testnet"] + payload[4:]))
                    descriptor = ref.export_policy(given["template"], network_keys, "testnet").descriptor
                    self_policy = ref.normalize_policy(given["template"], network_keys)
                    if policy != self_policy:
                        raise AssertionError("Network conversion changed normalization")
                    for selection in given["selections"]:
                        branch, index = selection["expansion"], selection["index"]
                        concrete = re.sub(r"/<([^>]+)>", lambda m: "/" + m[1].split(";")[branch], descriptor)
                        concrete = concrete.replace("/*", "/" + str(index))
                        internal_key = ref.derive_internal_key(policy, branch, index).hex()
                        explicit = "tr(" + internal_key + "," + concrete.split(",", 1)[1]
                        outputs = []
                        for candidate in (concrete, explicit):
                            canonical = rpc("getdescriptorinfo", candidate)["descriptor"]
                            outputs.append(rpc("deriveaddresses", canonical))
                        if outputs[0] != outputs[1]:
                            raise AssertionError(f"Core derivation mismatch: {case['name']} {selection}")
                        report["checks"].append({"name": case["name"], **selection,
                                                 "internal_key": internal_key, "addresses": outputs[0]})
                        by_name[case["name"], branch, index] = outputs[0]
                for left, right in (("single", "single-expanded"), ("sorted", "sorted-permuted"), ("tree", "tree-swapped")):
                    if by_name[left, 0, 0] != by_name[right, 0, 0]:
                        raise AssertionError("Equivalent exports produced different addresses")
                return report
            finally:
                if node.poll() is None:
                    node.terminate()
                    try:
                        node.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        node.kill()
                        node.wait()


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
