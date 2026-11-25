#!/usr/bin/env python3

"""
Driver script for generating test vector JSON files.
Outputs are saved in the "../vectors/" directory.
"""

from pathlib import Path

from gen_vector_utils import util
from gen_vector_utils.coordinator import (
    generate_coordinator_finalize_vectors,
    generate_coordinator_investigate_vectors,
    generate_coordinator_step1_vectors,
)
from gen_vector_utils.participant import (
    generate_participant_finalize_vectors,
    generate_participant_investigate_vectors,
    generate_participant_step1_vectors,
    generate_participant_step2_vectors,
)
from gen_vector_utils.session import (
    generate_hostpubkey_vectors,
    generate_params_hash_vectors,
    generate_recover_vectors,
)

output_dir = Path(__file__).parent.parent / "vectors"
output_dir.mkdir(parents=True, exist_ok=True)

util.write_json(
    output_dir / "hostpubkey_gen_vectors.json", generate_hostpubkey_vectors()
)
util.write_json(output_dir / "params_hash_vectors.json", generate_params_hash_vectors())
util.write_json(output_dir / "recover_vectors.json", generate_recover_vectors())
util.write_json(
    output_dir / "participant_step1_vectors.json",
    generate_participant_step1_vectors(),
)
util.write_json(
    output_dir / "participant_step2_vectors.json",
    generate_participant_step2_vectors(),
)
util.write_json(
    output_dir / "participant_finalize_vectors.json",
    generate_participant_finalize_vectors(),
)
util.write_json(
    output_dir / "participant_investigate_vectors.json",
    generate_participant_investigate_vectors(),
)
util.write_json(
    output_dir / "coordinator_step1_vectors.json",
    generate_coordinator_step1_vectors(),
)
util.write_json(
    output_dir / "coordinator_finalize_vectors.json",
    generate_coordinator_finalize_vectors(),
)
util.write_json(
    output_dir / "coordinator_investigate_vectors.json",
    generate_coordinator_investigate_vectors(),
)
print("Generated test vectors successfully")
