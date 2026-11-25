from typing import Any

from secp256k1lab.util import tagged_hash

BIP_TAG = "BIP DKG/"


def tagged_hash_bip_dkg(tag: str, msg: bytes) -> bytes:
    return tagged_hash(BIP_TAG + tag, msg)


class ProtocolError(Exception):
    """Base exception for errors caused by received protocol messages."""


class FaultyParticipantError(ProtocolError):
    """Raised if a participant is faulty.

    This exception is raised by the coordinator code when it detects faulty
    behavior by a participant, i.e., a participant has deviated from the
    protocol. The identifier of the participant is provided as part of the exception.
    Assuming protocol messages have been transmitted correctly and the
    coordinator itself is not faulty, this exception implies that the
    participant is indeed faulty.

    This exception is raised only by the coordinator code. Some faulty behavior
    by participants will be detected by the other participants instead.
    See `FaultyParticipantOrCoordinatorError` for details.

    Attributes:
        participant_id (int): Identifier of the faulty participant.
    """

    def __init__(self, participant_id: int, *args: Any):
        self.participant_id = participant_id
        super().__init__(participant_id, *args)


class FaultyParticipantOrCoordinatorError(ProtocolError):
    """Raised if another known participant or the coordinator is faulty.

    This exception is raised by the participant code when it detects what looks
    like faulty behavior by a suspected participant. The identifier of the suspected
    participant is provided as part of the exception.

    Importantly, this exception is not proof that the suspected participant is
    indeed faulty. It is instead possible that the coordinator has deviated from
    the protocol in a way that makes it look as if the suspected participant has
    deviated from the protocol. In other words, assuming messages have been
    transmitted correctly and the raising participant is not faulty, this
    exception implies that
      - the suspected participant is faulty,
      - *or* the coordinator is faulty (and has framed the suspected
        participant).

    This exception is raised only by the participant code. Some faulty behavior
    by participants will be detected by the coordinator instead. See
    `FaultyParticipantError` for details.

    Attributes:
        participant_id (int): Identifier of the suspected participant.
    """

    def __init__(self, participant_id: int, *args: Any):
        self.participant_id = participant_id
        super().__init__(participant_id, *args)


class FaultyCoordinatorError(ProtocolError):
    """Raised if the coordinator is faulty.

    This exception is raised by the participant code when it detects faulty
    behavior by the coordinator, i.e., the coordinator has deviated from the
    protocol. Assuming protocol messages have been transmitted correctly and the
    raising participant is not faulty, this exception implies that the
    coordinator is indeed faulty.
    """


class UnknownFaultyParticipantOrCoordinatorError(ProtocolError):
    """Raised if another unknown participant or the coordinator is faulty.

    This exception is raised by the participant code when it detects what looks
    like faulty behavior by some other participant, but there is insufficient
    information to determine which participant should be suspected.

    To determine a suspected participant, the raising participant may choose to
    run the optional investigation procedure of the protocol, which requires
    obtaining an investigation message from the coordinator. See the
    `participant_investigate` function for details.

    This is only raised for specific faulty behavior by another participant
    which cannot be attributed to another participant without further help of
    the coordinator (namely, sending invalid encrypted secret shares).

    Attributes:
        inv_data: Information required to perform the investigation.
    """

    def __init__(self, inv_data: Any, *args: Any):
        self.inv_data = inv_data
        super().__init__(*args)


class MsgParseError(ValueError):
    pass
