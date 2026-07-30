from __future__ import annotations

import json
from pathlib import Path
from typing import TypeAlias

from chilldkg_ref import chilldkg, encpedpop

ErrorInfo: TypeAlias = "dict[str, int | str | ErrorInfo]"


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: list[bytes]) -> list[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: list[str]) -> list[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


def write_json(filename: Path, data: dict) -> None:
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def exception_asdict(e: Exception) -> dict:
    error_info: ErrorInfo = {"type": e.__class__.__name__}

    for key, value in e.__dict__.items():
        if isinstance(value, (str, int)):
            error_info[key] = value
        elif isinstance(value, bytes):
            error_info[key] = bytes_to_hex(value)
        elif isinstance(value, encpedpop.ParticipantInvestigationData):
            continue
        else:
            raise NotImplementedError(
                f"Conversion for type {type(value).__name__} is not implemented"
            )

    # the last argument might contain the error message
    if len(e.args) > 0 and isinstance(e.args[-1], str):
        error_info.setdefault("message", e.args[-1])

    # Update snake case keys into camel case keys to match the JSON vector format
    for key in list(error_info.keys()):
        if "_" in key:
            camel_case_key = "".join(
                word.capitalize() if i > 0 else word
                for i, word in enumerate(key.split("_"))
            )
            error_info[camel_case_key] = error_info.pop(key)

    return error_info


def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_asdict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")


def expect_faulty_exception(try_fn, expected_exception, expected_participant_id):
    error = expect_exception(try_fn, expected_exception)
    actual = error.get("participantId")
    assert actual == expected_participant_id, (
        f"expected faulty participant {expected_participant_id}, got {actual}"
    )
    return error


def params_asdict(params: chilldkg.SessionParams) -> dict:
    return {"hostpubkeys": bytes_list_to_hex(params.hostpubkeys), "t": params.t}


def dkg_output_asdict(dkg_output: chilldkg.DKGOutput) -> dict:
    secshare = bytes_to_hex(dkg_output.secshare) if dkg_output.secshare else None
    return {
        "secshare": secshare,
        "threshPk": bytes_to_hex(dkg_output.thresh_pk),
        "pubshares": bytes_list_to_hex(dkg_output.pubshares),
    }


def assign_tc_ids(groups):
    tc_id = 1
    for group in groups:
        for key in ("validTestCases", "errorTestCases"):
            for i, case in enumerate(group.get(key, [])):
                assert "tcId" not in case
                group[key][i] = {"tcId": tc_id, **case}
                tc_id += 1
    return tc_id - 1


# functions below are used to test JSON vectors with chilldkg_ref
# in tests.py


def assert_raises(try_fn, expected_error: dict):
    try:
        try_fn()
    except Exception as e:
        assert expected_error == exception_asdict(e)
    else:
        raise AssertionError("Expected exception")


def params_from_dict(params: dict) -> chilldkg.SessionParams:
    return chilldkg.SessionParams(
        hex_list_to_bytes(params["hostpubkeys"]),
        params["t"],
    )
