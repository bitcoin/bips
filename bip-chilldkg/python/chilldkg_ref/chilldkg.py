"""Reference implementation of ChillDKG.

WARNING: This code is slow and trivially vulnerable to side channel attacks. Do
not use for anything but tests.

The public API consists of all functions with docstrings, including the types in
their arguments and return values, and the exceptions they raise; see also the
`__all__` list. All other definitions are internal.

In addition to the exceptions documented for each function, all public API
functions may raise Python built-in exceptions such as `TypeError` or
`ValueError` when called with arguments of unexpected structure (e.g., wrong
type or wrong length). These structural errors are not documented per function.
"""

from __future__ import annotations

from typing import Any, NamedTuple, NewType, NoReturn

from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import GE, Scalar
from secp256k1lab.util import bytes_from_int

from . import encpedpop
from .util import (
    BIP_TAG,
    FaultyCoordinatorError,
    FaultyParticipantError,
    FaultyParticipantOrCoordinatorError,
    MsgParseError,
    ProtocolError,
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
)
from .vss import VSSCommitment

__all__ = [
    # Functions
    "hostpubkey_gen",
    "params_hash",
    "participant_step1",
    "participant_step2",
    "participant_finalize",
    "participant_investigate",
    "coordinator_step1",
    "coordinator_finalize",
    "coordinator_investigate",
    "participant_recover",
    "coordinator_recover",
    "participant_recovery_ack_sign",
    "participant_recovery_acks_verify",
    # Exceptions
    "HostSeckeyError",
    "SessionParamsError",
    "InvalidHostPubkeyError",
    "DuplicateHostPubkeyError",
    "ThresholdOrCountError",
    "RandomnessError",
    "ProtocolError",
    "FaultyParticipantError",
    "FaultyParticipantOrCoordinatorError",
    "FaultyCoordinatorError",
    "UnknownFaultyParticipantOrCoordinatorError",
    "RecoveryDataError",
    "InvalidRecoveryAckError",
    # Types
    "SessionParams",
    "DKGOutput",
    "ParticipantState1",
    "ParticipantState2",
    "CoordinatorState",
    "RecoveryData",
]


###
### Equality check protocol CertEq
###


def certeq_message(x: bytes, participant_id: int) -> bytes:
    # Domain separation as described in BIP 340
    prefix = (BIP_TAG + "certeq message").encode()
    prefix = prefix + b"\x00" * (33 - len(prefix))
    assert len(prefix) == 33
    return prefix + participant_id.to_bytes(4, "big") + x


def certeq_participant_step(
    hostseckey: bytes, participant_id: int, x: bytes, aux_rand: bytes
) -> bytes:
    msg = certeq_message(x, participant_id)
    return schnorr_sign(msg, hostseckey, aux_rand=aux_rand)


def certeq_cert_len(n: int) -> int:
    return 64 * n


def certeq_verify(hostpubkeys: list[bytes], x: bytes, cert: bytes) -> None:
    n = len(hostpubkeys)
    if len(cert) != certeq_cert_len(n):
        raise ValueError
    for i in range(n):
        msg = certeq_message(x, i)
        valid = schnorr_verify(
            msg,
            # Dropping the sign byte from hostpubkeys[i] is okay because msg
            # commits on the full hostpubkeys[i]: it encodes all hostpubkeys
            # together with the id i.
            hostpubkeys[i][1:33],
            cert[i * 64 : (i + 1) * 64],
        )
        if not valid:
            raise InvalidSignatureInCertificateError(i)


def certeq_coordinator_step(sigs: list[bytes]) -> bytes:
    cert = b"".join(sigs)
    return cert


class InvalidSignatureInCertificateError(ValueError):
    def __init__(self, participant_id: int, *args: Any):
        self.participant_id = participant_id
        super().__init__(participant_id, *args)


###
### Recovery acknowledgment helpers
###


def recovery_ack_message(x: bytes, participant_id: int) -> bytes:
    # Domain separation as described in BIP 340
    prefix = (BIP_TAG + "recovery acknowledgment").encode()
    prefix = prefix + b"\x00" * (33 - len(prefix))
    assert len(prefix) == 33
    return prefix + participant_id.to_bytes(4, "big") + x


def recovery_ack_sign(
    hostseckey: bytes, participant_id: int, x: bytes, aux_rand: bytes
) -> bytes:
    msg = recovery_ack_message(x, participant_id)
    return schnorr_sign(msg, hostseckey, aux_rand=aux_rand)


###
### Host keys
###


def hostpubkey_gen(hostseckey: bytes) -> bytes:
    """Compute the participant's host public key from the host secret key.

    The host public key is the long-term cryptographic identity of the
    participant.

    This function interprets `hostseckey` as big-endian integer, and computes
    the corresponding "plain" public key in compressed serialization (33 bytes,
    starting with 0x02 or 0x03). This is the key generation procedure
    traditionally used in Bitcoin, e.g., for ECDSA. In other words, this
    function is equivalent to `IndividualPubkey` as defined in
    [[BIP 327](bip-0327.mediawiki#key-generation-of-an-individual-signer)].

    Arguments:
        hostseckey: This participant's long-term secret key (32 bytes).
            The key **must** be 32 bytes of cryptographically secure randomness
            with sufficient entropy to be unpredictable. All outputs of a
            successful participant in a session can be recovered from (a backup
            of) the key and per-session recovery data.

            The same host secret key (and thus the same host public key) can be
            used in multiple DKG sessions. A host public key can be correlated
            to the threshold public key resulting from a DKG session only by
            parties who observed the session, namely the participants, the
            coordinator (and any eavesdropper).

    Returns:
        The host public key (33 bytes).

    Raises:
        HostSeckeyError: If the host secret key is invalid.
    """
    if len(hostseckey) != 32:
        raise ValueError

    try:
        return pubkey_gen_plain(hostseckey)
    except ValueError:
        raise HostSeckeyError


class HostSeckeyError(ValueError):
    """Raised if the host secret key is invalid."""


###
### Session input and outputs
###


# It would be more idiomatic Python to make this a real (data)class, perform
# data validation in the constructor, and add methods to it, but let's stick to
# simple tuples in the public API in order to keep it approachable to readers
# who are not too familiar with Python.
class SessionParams(NamedTuple):
    """A `SessionParams` tuple holds the common parameters of a DKG session.

    Attributes:
        hostpubkeys: Ordered list of the host public keys of all participants.
        t: The participation threshold `t`.
            This is the number of participants that will be required to sign.
            It must hold that `1 <= t <= len(hostpubkeys) <= 2**32 - 1`.

    Each participant **must** ensure to have authentic copies of all other
    participants' host public keys before the start of the session, e.g., by
    confirming authenticity of each host public key with the expected key
    holder out of band. This is analogous to traditional threshold signatures
    (known as "multisig" in the Bitcoin community),
    [[BIP 383](bip-0383.mediawiki)], where a signer needs the other signers'
    authentic extended public keys ("xpubs") to generate multisig addresses,
    or MuSig2 [[BIP 327](bip-0327.mediawiki)], where a signer needs the other
    participants' authentic individual public keys to generate an aggregated
    public key.

    A DKG session will fail if the participants and the coordinator in a session
    don't have the `hostpubkeys` in the same order. This will make sure that
    honest participants agree on the order as part of the session, which is
    useful if the order carries an implicit meaning in the application (e.g., if
    the first `t` participants are the primary participants for signing and the
    others are fallback participants). If there is no canonical order of the
    participants in the application, the caller can sort the list of host public
    keys with the [KeySort algorithm specified in
    BIP 327](bip-0327.mediawiki#key-sorting) to abstract away from the order.
    """

    hostpubkeys: list[bytes]
    t: int


def params_validate(params: SessionParams) -> None:
    (hostpubkeys, t) = params

    if not (1 <= t <= len(hostpubkeys) <= 2**32 - 1):
        raise ThresholdOrCountError

    # Check that all hostpubkeys are valid
    for i, hostpubkey in enumerate(hostpubkeys):
        try:
            _ = GE.from_bytes_compressed(hostpubkey)
        except ValueError as e:
            raise InvalidHostPubkeyError(i) from e

    # Check for duplicate hostpubkeys and find the corresponding ids
    hostpubkey_to_id: dict[bytes, int] = {}
    for i, hostpubkey in enumerate(hostpubkeys):
        if hostpubkey in hostpubkey_to_id:
            raise DuplicateHostPubkeyError(hostpubkey_to_id[hostpubkey], i)
        hostpubkey_to_id[hostpubkey] = i


def params_hash(params: SessionParams) -> bytes:
    """Return a hash of the session parameters for out-of-band comparison.

    In the common scenario that the participants obtain host public keys from
    the other participants over channels that do not provide end-to-end
    authentication of the sending participant (e.g., if the participants simply
    send their unauthenticated host public keys to the coordinator, who is
    supposed to relay them to all participants), the parameters hash serves as a
    convenient way to perform an out-of-band comparison of all host public keys.
    It is a collision-resistant cryptographic hash of the `SessionParams` tuple.
    As a result, if all participants have obtained an identical parameters hash
    (as can be verified out-of-band), then they all agree on all host public
    keys and the threshold `t`, and in particular, all participants have
    obtained authentic public host keys.

    Returns:
        bytes: The parameters hash, a 32-byte string.

    Raises:
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
    """
    params_validate(params)
    hostpubkeys, t = params

    t_bytes = t.to_bytes(4, byteorder="big")
    params_hash = tagged_hash_bip_dkg(
        "params_hash",
        t_bytes + b"".join(hostpubkeys),
    )
    assert len(params_hash) == 32
    return params_hash


class SessionParamsError(ValueError):
    """Base exception for invalid `SessionParams` tuples."""


class DuplicateHostPubkeyError(SessionParamsError):
    """Raised if two participants have identical host public keys.

    This exception is raised when two participants have an identical host public
    key in the `SessionParams` tuple. Assuming the host public keys in question
    have been transmitted correctly, this exception implies that at least one of
    the two participants is faulty (because duplicates occur only with
    negligible probability if keys are generated honestly).

    Attributes:
        participant_id1 (int): Identifier of the first participant.
        participant_id2 (int): Identifier of the second participant.
    """

    def __init__(self, participant_id1: int, participant_id2: int, *args: Any):
        self.participant_id1 = participant_id1
        self.participant_id2 = participant_id2
        super().__init__(participant_id1, participant_id2, *args)


class InvalidHostPubkeyError(SessionParamsError):
    """Raised if a host public key is invalid.

    This exception is raised when a host public key in the `SessionParams` tuple
    is not a valid public key in compressed serialization. Assuming the host
    public keys in question has been transmitted correctly, this exception
    implies that the corresponding participant is faulty.

    Attributes:
        participant_id (int): Identifier of the participant.
    """

    def __init__(self, participant_id: int, *args: Any):
        self.participant_id = participant_id
        super().__init__(participant_id, *args)


class ThresholdOrCountError(SessionParamsError):
    """Raised if `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does not hold."""


# This is really the same definition as in simplpedpop and encpedpop. We repeat
# it here only to have its docstring in this module.
class DKGOutput(NamedTuple):
    """Holds the outputs of a DKG session.

    Attributes:
        secshare: Secret share of the participant (32 bytes, or `None` for
            coordinator).
        thresh_pk: Generated threshold public key representing the group
            (33 bytes, in compressed serialization).
        pubshares: Public shares of the participants (33 bytes each, in
            compressed serialization).
    """

    secshare: bytes | None
    thresh_pk: bytes
    pubshares: list[bytes]


RecoveryData = NewType("RecoveryData", bytes)


###
### Messages
###


class ParticipantMsg1(NamedTuple):
    enc_pmsg: encpedpop.ParticipantMsg

    @staticmethod
    def len_bytes(*, t: int, n: int) -> int:
        return encpedpop.ParticipantMsg.len_bytes(t=t, n=n)

    @staticmethod
    def from_bytes(b: bytes, *, t: int, n: int) -> ParticipantMsg1:
        if len(b) != ParticipantMsg1.len_bytes(t=t, n=n):
            raise ValueError
        enc_pmsg = encpedpop.ParticipantMsg.from_bytes(
            b, t=t, n=n
        )  # MsgParseError if invalid
        return ParticipantMsg1(enc_pmsg)

    def to_bytes(self) -> bytes:
        return self.enc_pmsg.to_bytes()


class ParticipantMsg2(NamedTuple):
    sig: bytes

    @staticmethod
    def len_bytes() -> int:
        return 64

    @staticmethod
    def from_bytes(b: bytes) -> ParticipantMsg2:
        if len(b) != ParticipantMsg2.len_bytes():
            raise ValueError
        return ParticipantMsg2(b)

    def to_bytes(self) -> bytes:
        return self.sig


class CoordinatorMsg1(NamedTuple):
    enc_cmsg: encpedpop.CoordinatorMsg
    enc_secshares: list[Scalar]

    @staticmethod
    def len_bytes(*, t: int, n: int) -> int:
        return encpedpop.CoordinatorMsg.len_bytes(t=t, n=n) + 32 * n

    @staticmethod
    def from_bytes(b: bytes, *, t: int, n: int) -> CoordinatorMsg1:
        if len(b) != CoordinatorMsg1.len_bytes(t=t, n=n):
            raise ValueError

        # Read enc_cmsg
        enc_cmsg_len = encpedpop.CoordinatorMsg.len_bytes(t=t, n=n)
        enc_cmsg, rest = (
            encpedpop.CoordinatorMsg.from_bytes(b[:enc_cmsg_len], t=t, n=n),
            b[enc_cmsg_len:],
        )  # MsgParseError if invalid

        # Read enc_secshares (32*n bytes)
        try:
            enc_secshares = [
                Scalar.from_bytes_checked(rest[i : i + 32])  # ValueError if overflow
                for i in range(0, 32 * n, 32)
            ]
        except ValueError as e:
            raise MsgParseError("invalid encrypted secret shares") from e

        return CoordinatorMsg1(enc_cmsg, enc_secshares)

    def to_bytes(self) -> bytes:
        return self.enc_cmsg.to_bytes() + b"".join(
            share.to_bytes() for share in self.enc_secshares
        )


class CoordinatorMsg2(NamedTuple):
    cert: bytes

    @staticmethod
    def len_bytes(*, n: int) -> int:
        return certeq_cert_len(n)

    @staticmethod
    def from_bytes(b: bytes, *, n: int) -> CoordinatorMsg2:
        if len(b) != CoordinatorMsg2.len_bytes(n=n):
            raise ValueError
        return CoordinatorMsg2(b)

    def to_bytes(self) -> bytes:
        return self.cert


class CoordinatorInvestigationMsg(NamedTuple):
    enc_cinv: encpedpop.CoordinatorInvestigationMsg

    @staticmethod
    def len_bytes(*, n: int) -> int:
        return encpedpop.CoordinatorInvestigationMsg.len_bytes(n=n)

    @staticmethod
    def from_bytes(b: bytes, *, n: int) -> CoordinatorInvestigationMsg:
        if len(b) != CoordinatorInvestigationMsg.len_bytes(n=n):
            raise ValueError
        enc_cinv = encpedpop.CoordinatorInvestigationMsg.from_bytes(
            b, n=n
        )  # MsgParseError if invalid
        return CoordinatorInvestigationMsg(enc_cinv)

    def to_bytes(self) -> bytes:
        return self.enc_cinv.to_bytes()


class RecoveryAckMsg(NamedTuple):
    sig: bytes

    @staticmethod
    def len_bytes() -> int:
        return 64

    @staticmethod
    def from_bytes(b: bytes) -> RecoveryAckMsg:
        if len(b) != RecoveryAckMsg.len_bytes():
            raise ValueError
        return RecoveryAckMsg(b)

    def to_bytes(self) -> bytes:
        return self.sig


def deserialize_recovery_data(
    b: bytes,
) -> tuple[int, VSSCommitment, list[bytes], list[bytes], list[Scalar], bytes]:
    rest = b

    # Read t (4 bytes)
    if len(rest) < 4:
        raise ValueError
    t, rest = int.from_bytes(rest[:4], byteorder="big"), rest[4:]

    # Read sum_coms (33*t bytes)
    if len(rest) < 33 * t:
        raise ValueError
    sum_coms, rest = (
        VSSCommitment.from_bytes(rest[: 33 * t], t=t),
        rest[33 * t :],
    )

    # Compute n
    n, remainder = divmod(len(rest), (33 + 33 + 32 + 64))
    if remainder != 0:
        raise ValueError

    # Read hostpubkeys (33*n bytes)
    assert len(rest) >= 33 * n
    hostpubkeys, rest = [rest[i : i + 33] for i in range(0, 33 * n, 33)], rest[33 * n :]

    # Read pubnonces (33*n bytes)
    assert len(rest) >= 33 * n
    pubnonces, rest = [rest[i : i + 33] for i in range(0, 33 * n, 33)], rest[33 * n :]

    # Read enc_secshares (32*n bytes)
    assert len(rest) >= 32 * n
    enc_secshares, rest = (
        [Scalar.from_bytes_checked(rest[i : i + 32]) for i in range(0, 32 * n, 32)],
        rest[32 * n :],
    )

    # Read cert (64*n bytes)
    assert len(rest) >= 64 * n
    cert, rest = rest[: 64 * n], rest[64 * n :]

    assert len(rest) == 0
    return (t, sum_coms, hostpubkeys, pubnonces, enc_secshares, cert)


###
### Participant
###


class ParticipantState1(NamedTuple):
    params: SessionParams
    participant_id: int
    enc_state: encpedpop.ParticipantState


class ParticipantState2(NamedTuple):
    params: SessionParams
    eq_input: bytes
    dkg_output: DKGOutput


def participant_step1(
    hostseckey: bytes, params: SessionParams, random: bytes
) -> tuple[ParticipantState1, bytes]:
    """Perform a participant's first step of a ChillDKG session.

    Arguments:
        hostseckey: Participant's long-term host secret key (32 bytes).
        params: Common session parameters.
        random: FRESH random byte string (32 bytes).

    Returns:
        ParticipantState1: The participant's session state after this step, to
            be passed as an argument to `participant_step2`. The state **must
            not** be reused (i.e., it must be passed only to one
            `participant_step2` call).
        bytes: The first message to be sent to the coordinator
            (`33*t + 32*n + 97` bytes).

    Raises:
        HostSeckeyError: If the host secret key is invalid, or if the key does
            not match any entry of `hostpubkeys`.
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
        RandomnessError: If `random` is all zeroes (i.e., `b"\\x00" * 32`). This
            check guards against the case of a malfunctioning random number
            generator.
    """
    hostpubkey = hostpubkey_gen(hostseckey)  # ValueError if len(hostseckey) != 32

    params_validate(params)
    (hostpubkeys, t) = params

    try:
        participant_id = hostpubkeys.index(hostpubkey)
    except ValueError as e:
        raise HostSeckeyError(
            "Host secret key does not match any host public key"
        ) from e
    if len(random) != 32:
        raise ValueError
    if random == b"\x00" * 32:
        raise RandomnessError

    enc_state, enc_pmsg = encpedpop.participant_step1(
        # We know that EncPedPop uses its seed only by feeding it to a hash
        # function. Thus, it is sufficient that the seed has a high entropy,
        # and so we can simply pass the hostseckey as seed.
        seed=hostseckey,
        deckey=hostseckey,
        t=t,
        # This requires the joint security of Schnorr signatures and ECDH.
        enckeys=hostpubkeys,
        participant_id=participant_id,
        random=random,
    )

    state1 = ParticipantState1(params, participant_id, enc_state)
    pmsg1 = enc_pmsg
    return state1, pmsg1


class RandomnessError(ValueError):
    """Raised if the randomness is all zeroes (i.e., `b"\\x00" * 32`)."""


def participant_step2(
    hostseckey: bytes,
    state1: ParticipantState1,
    cmsg1: bytes,
    aux_rand: bytes,
) -> tuple[ParticipantState2, bytes]:
    """Perform a participant's second step of a ChillDKG session.

    **Warning:**
    After sending the returned message to the coordinator, the caller **must
    not** erase the hostseckey, even if the coordinator reply needed for the
    `participant_finalize` call is not received. The underlying reason is that
    some other participant may receive the coordinator reply, deem the DKG
    session successful and use the resulting threshold public key (e.g., by
    sending funds to it). If the coordinator reply remains missing, that other
    participant can, at any point in the future, convince this participant of
    the success of the DKG session by presenting recovery data, from which this
    participant can recover the DKG output using the `participant_recover`
    function.

    Arguments:
        hostseckey: Participant's long-term host secret key (32 bytes).
        state1: The participant's session state as output by
            `participant_step1`.
        cmsg1: The first message received from the coordinator
            (`162*n + 33*(t-1)` bytes).
        aux_rand: Auxiliary randomness (32 bytes). FRESH 32-byte randomness
            is optimal, but 16 random bytes or a counter padded to 32 bytes
            is acceptable (see BIP 340).

    Returns:
        ParticipantState2: The participant's session state after this step, to
            be passed as an argument to `participant_finalize`. The state **must
            not** be reused (i.e., it must be passed only to one
            `participant_finalize` call).
        bytes: The second message to be sent to the coordinator (64 bytes).

    Raises:
        HostSeckeyError: If the host secret key is invalid or if it does not
            match the one used in `participant_step1`.
        FaultyCoordinatorError: If the coordinator is faulty. See the
            documentation of the exception for further details.
        FaultyParticipantOrCoordinatorError: If another known participant or the
            coordinator is faulty. See the documentation of the exception for
            further details.
        UnknownFaultyParticipantOrCoordinatorError: If another unknown
            participant or the coordinator is faulty, but running the optional
            investigation procedure of the protocol is necessary to determine a
            suspected participant. See the documentation of the exception for
            further details.
    """
    hostpubkey = hostpubkey_gen(
        hostseckey
    )  # HostSeckeyError if invalid or ValueError if len(hostseckey) != 32
    if len(aux_rand) != 32:
        raise ValueError

    params, participant_id, enc_state = state1
    if hostpubkey != params.hostpubkeys[participant_id]:
        raise HostSeckeyError(
            "Host secret key does not match the one used in participant_step1"
        )
    t = enc_state.simpl_state.t
    try:
        cmsg1_parsed = CoordinatorMsg1.from_bytes(cmsg1, t=t, n=len(params.hostpubkeys))
    except MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    enc_cmsg, enc_secshares = cmsg1_parsed

    enc_dkg_output, eq_input = encpedpop.participant_step2(
        state=enc_state,
        deckey=hostseckey,
        cmsg=enc_cmsg.to_bytes(),
        enc_secshare=enc_secshares[participant_id],
    )

    # Include the enc_shares in eq_input to ensure that participants agree on
    # all shares, which in turn ensures that they have the right recovery data.
    eq_input += b"".join([bytes_from_int(int(share)) for share in enc_secshares])
    dkg_output = DKGOutput._make(enc_dkg_output)
    state2 = ParticipantState2(params, eq_input, dkg_output)
    sig = certeq_participant_step(hostseckey, participant_id, eq_input, aux_rand)
    pmsg2 = ParticipantMsg2(sig).to_bytes()
    return state2, pmsg2


def participant_finalize(
    state2: ParticipantState2, cmsg2: bytes
) -> tuple[DKGOutput, RecoveryData]:
    """Perform a participant's final step of a ChillDKG session.

    If this function returns properly (without an exception), then this
    participant deems the DKG session successful. It is, however, possible that
    other participants have received a `cmsg2` from the coordinator that made
    them raise an exception instead, or that they have not received a `cmsg2`
    from the coordinator at all. These participants can, at any point in time in
    the future (e.g., when initiating a signing session), be convinced to deem
    the session successful by presenting the recovery data to them, from which
    they can recover the DKG outputs using the `participant_recover` function.

    Since returning successfully does not imply that other participants deem
    the DKG session successful, returning successfully also does not imply
    that redundant copies of the recovery data exist. For example, it could
    be the case that other participants raised an exception instead, and this
    participant will be the only one that obtained the recovery data. In that
    case, if this participant's storage fails, the only copy of the recovery
    data is lost. As a result, this participant will not be able to convince
    any other participants to deem the DKG session successful, and it will
    not be possible to create a signature.

    To protect against this scenario, callers **should** ensure that all
    participants deem the DKG session successful (which also implies that
    they have a redundant copy of the recovery data) before using the
    threshold public key (e.g., before sending funds to it). The recommended
    way of doing so is by collecting acknowledgment signatures via
    `participant_recovery_ack_sign`. Callers can alternatively employ some
    other means to ensure that they will always have access to the recovery
    data (which can be used to convince other participants that the DKG
    session was successful). For example, they could use a custom redundant
    way of backing up the recovery data.

    **Warning:**
    Changing perspectives, this implies that, even when obtaining an exception,
    the caller **must not** conclude that the DKG session has failed, and as a
    consequence, the caller **must not** erase the hostseckey. The underlying
    reason is that some other participant may deem the DKG session successful
    and use the resulting threshold public key (e.g., by sending funds to it).
    That other participant can, at any point in the future, convince this
    participant of the success of the DKG session by presenting recovery data to
    this participant.

    Arguments:
        state2: The participant's state as output by `participant_step2`.
        cmsg2: The second message received from the coordinator
            (`64*n` bytes).

    Returns:
        DKGOutput: The DKG output.
        bytes: The serialized recovery data.

    Raises:
        FaultyCoordinatorError: If the coordinator is faulty. See the
            documentation of the exception for further details.
    """
    params, eq_input, dkg_output = state2
    cmsg2_parsed = CoordinatorMsg2.from_bytes(cmsg2, n=len(params.hostpubkeys))
    try:
        certeq_verify(params.hostpubkeys, eq_input, cmsg2_parsed.cert)
    except InvalidSignatureInCertificateError as e:
        raise FaultyCoordinatorError(
            "Coordinator has provided a certificate with an invalid signature"
        ) from e
    return dkg_output, RecoveryData(eq_input + cmsg2_parsed.cert)


def participant_investigate(
    error: UnknownFaultyParticipantOrCoordinatorError,
    cinv: bytes,
) -> NoReturn:
    """Investigate who is to blame for a failed ChillDKG session.

    This function can optionally be called when `participant_step2` raises
    `UnknownFaultyParticipantOrCoordinatorError`. It narrows down the suspected
    faulty parties by analyzing the investigation message provided by the
    coordinator.

    This function does not return normally. Instead, it raises one of two
    exceptions.

    Arguments:
        error: `UnknownFaultyParticipantOrCoordinatorError` raised by
            `participant_step2`.
        cinv: Coordinator investigation message for this participant as output
            by `coordinator_investigate` (`65*n` bytes).

    Raises:
        FaultyParticipantOrCoordinatorError: If another known participant or the
            coordinator is faulty. See the documentation of the exception for
            further details.
        FaultyCoordinatorError: If the coordinator is faulty. See the
            documentation of the exception for further details.
    """
    assert isinstance(error.inv_data, encpedpop.ParticipantInvestigationData)
    n = error.inv_data.simpl_bstate.n
    try:
        cinv_parsed = CoordinatorInvestigationMsg.from_bytes(cinv, n=n)
    except MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    encpedpop.participant_investigate(
        error=error,
        cinv=cinv_parsed.enc_cinv.to_bytes(),
    )


###
### Coordinator
###


class CoordinatorState(NamedTuple):
    params: SessionParams
    eq_input: bytes
    dkg_output: DKGOutput


def coordinator_step1(
    pmsgs1: list[bytes], params: SessionParams
) -> tuple[CoordinatorState, bytes]:
    """Perform the coordinator's first step of a ChillDKG session.

    Arguments:
        pmsgs1: List of first messages received from the participants
                (`33*t + 32*n + 97` bytes each). The list's length must equal
                the total number of participants.
        params: Common session parameters.

    Returns:
        CoordinatorState: The coordinator's session state after this step, to be
            passed as an argument to `coordinator_finalize`. The state is not
            supposed to be reused (i.e., it is supposed to be passed only to one
            `coordinator_finalize` call).
        bytes: The first message to be sent to all participants
            (`162*n + 33*(t-1)` bytes).

    Raises:
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
        FaultyParticipantError: If a participant is faulty. See the
            documentation of the exception for further details.
    """
    params_validate(params)
    hostpubkeys, t = params
    if len(pmsgs1) != len(hostpubkeys):
        raise ValueError

    pmsgs1_parsed = []
    for participant_id, pmsg1 in enumerate(pmsgs1):
        try:
            parsed = ParticipantMsg1.from_bytes(pmsg1, t=t, n=len(hostpubkeys))
        except MsgParseError as e:
            raise FaultyParticipantError(participant_id, *e.args) from e
        pmsgs1_parsed.append(parsed)

    enc_cmsg, enc_dkg_output, eq_input, enc_secshares = encpedpop.coordinator_step(
        pmsgs=[pmsg1.enc_pmsg.to_bytes() for pmsg1 in pmsgs1_parsed],
        t=t,
        enckeys=hostpubkeys,
    )
    enc_cmsg_parsed = encpedpop.CoordinatorMsg.from_bytes(
        enc_cmsg, t=t, n=len(hostpubkeys)
    )
    eq_input += b"".join([bytes_from_int(int(share)) for share in enc_secshares])
    dkg_output = DKGOutput._make(enc_dkg_output)  # Convert to chilldkg.DKGOutput type
    state = CoordinatorState(params, eq_input, dkg_output)
    cmsg1 = CoordinatorMsg1(enc_cmsg_parsed, enc_secshares).to_bytes()
    return state, cmsg1


def coordinator_finalize(
    state: CoordinatorState, pmsgs2: list[bytes]
) -> tuple[bytes, DKGOutput, RecoveryData]:
    """Perform the coordinator's final step of a ChillDKG session.

    If this function returns properly (without an exception), then the
    coordinator deems the DKG session successful. The returned `CoordinatorMsg2`
    is supposed to be sent to all participants, who are supposed to pass it as
    input to the `participant_finalize` function. It is, however, possible that
    some participants pass a wrong and invalid message to `participant_finalize`
    (e.g., because the message is transmitted incorrectly). These participants
    can, at any point in time in the future (e.g., when initiating a signing
    session), be convinced to deem the session successful by presenting the
    recovery data to them, from which they can recover the DKG outputs using the
    `participant_recover` function.

    If this function raises an exception, then the DKG session was not
    successful from the perspective of the coordinator. In this case, it is, in
    principle, possible to recover the DKG outputs of the coordinator using the
    `coordinator_recover` function together with the recovery data from a
    successful participant, should one exist. Any such successful participant
    is either faulty, or has received messages from other participants via a
    communication channel beside the coordinator.

    Arguments:
        state: The coordinator's session state as output by `coordinator_step1`.
        pmsgs2: List of second messages received from the participants
                (64 bytes each). The list's length must equal the total number
                of participants.

    Returns:
        bytes: The second message to be sent to all participants (`64*n` bytes).
        DKGOutput: The DKG output. Since the coordinator does not have a secret
            share, the DKG output will have the `secshare` field set to `None`.
        bytes: The serialized recovery data.

    Raises:
        FaultyParticipantError: If a participant is faulty. See the
            documentation of the exception for further details.
    """
    params, eq_input, dkg_output = state
    if len(pmsgs2) != len(params.hostpubkeys):
        raise ValueError

    pmsgs2_parsed = [ParticipantMsg2.from_bytes(pmsg2) for pmsg2 in pmsgs2]
    cert = certeq_coordinator_step([pmsg2.sig for pmsg2 in pmsgs2_parsed])
    try:
        certeq_verify(params.hostpubkeys, eq_input, cert)
    except InvalidSignatureInCertificateError as e:
        raise FaultyParticipantError(
            e.participant_id,
            "Participant has provided an invalid signature for the certificate",
        ) from e
    cmsg2 = CoordinatorMsg2(cert).to_bytes()
    return cmsg2, dkg_output, RecoveryData(eq_input + cert)


def coordinator_investigate(pmsgs: list[bytes], params: SessionParams) -> list[bytes]:
    """Generate investigation messages for a ChillDKG session.

    The investigation messages will allow the participants to investigate who is
    to blame for a failed ChillDKG session (see `participant_investigate`).

    Each message is intended for a single participant but can be safely
    broadcast to all participants because the messages contain no confidential
    information.

    Arguments:
        pmsgs: List of serialized first messages received from the participants
               (`33*t + 32*n + 97` bytes each).
        params: Common session parameters.

    Returns:
        List[bytes]: A list of investigation messages, each intended for a
            single participant (`65*n` bytes each).

    Raises:
        FaultyParticipantError: If a participant is faulty. See the
            documentation of the exception for further details.
    """
    n = len(pmsgs)
    t = params.t
    pmsgs_parsed = []
    for participant_id, pmsg in enumerate(pmsgs):
        try:
            parsed = ParticipantMsg1.from_bytes(pmsg, t=t, n=n)
        except MsgParseError as e:
            raise FaultyParticipantError(participant_id, *e.args) from e
        pmsgs_parsed.append(parsed)
    enc_cinvs = encpedpop.coordinator_investigate(
        [pmsg.enc_pmsg.to_bytes() for pmsg in pmsgs_parsed], t
    )
    return enc_cinvs


###
### Recovery
###


def recover(
    hostseckey: bytes | None, recovery_data: RecoveryData
) -> tuple[DKGOutput, SessionParams]:
    try:
        (t, sum_coms, hostpubkeys, pubnonces, enc_secshares, cert) = (
            deserialize_recovery_data(recovery_data)
        )
    except Exception as e:
        raise RecoveryDataError("Failed to deserialize recovery data") from e

    n = len(hostpubkeys)
    params = SessionParams(hostpubkeys, t)
    try:
        params_validate(params)
    except SessionParamsError as e:
        raise RecoveryDataError("Invalid session parameters in recovery data") from e

    # Verify cert
    eq_input = recovery_data[: -len(cert)]
    try:
        certeq_verify(hostpubkeys, eq_input, cert)
    except InvalidSignatureInCertificateError as e:
        raise RecoveryDataError("Invalid certificate in recovery data") from e

    # Compute threshold pubkey and individual pubshares
    sum_coms, tweak, _ = sum_coms.invalid_taproot_commit()
    thresh_pk = sum_coms.commitment_to_secret()
    pubshares = [sum_coms.pubshare(i) for i in range(n)]

    if hostseckey is not None:
        hostpubkey = hostpubkey_gen(hostseckey)  # ValueError or HostSeckeyError
        try:
            participant_id = hostpubkeys.index(hostpubkey)
        except ValueError as e:
            raise HostSeckeyError(
                "Host secret key does not match any host public key in the recovery data"
            ) from e

        # Decrypt share
        enc_context = encpedpop.serialize_enc_context(t, hostpubkeys)
        secshare = encpedpop.decrypt_sum(
            hostseckey,
            hostpubkeys[participant_id],
            pubnonces,
            enc_context,
            participant_id,
            enc_secshares[participant_id],
        )
        secshare_tweaked = secshare + tweak

        # This is just a sanity check. Our signature is valid, so we have done
        # an equivalent check already during the actual session.
        assert VSSCommitment.verify_secshare(
            secshare_tweaked, pubshares[participant_id]
        )
    else:
        secshare_tweaked = None

    dkg_output = DKGOutput(
        None if secshare_tweaked is None else secshare_tweaked.to_bytes(),
        thresh_pk.to_bytes_compressed(),
        [pubshare.to_bytes_compressed() for pubshare in pubshares],
    )
    return dkg_output, params


def participant_recover(
    hostseckey: bytes, recovery_data: RecoveryData
) -> tuple[DKGOutput, SessionParams]:
    """Recover the DKG output of a participant of a ChillDKG session.

    This function serves two different purposes:
    1. To recover from an exception in `participant_finalize`, after
       obtaining the recovery data from another participant or the
       coordinator. See `participant_finalize` for background.
    2. To reproduce the DKG outputs on a new device, e.g., to recover from a
       backup after data loss.

    Arguments:
        hostseckey: This participant's long-term host secret key (32 bytes).
        recovery_data: Recovery data from a successful session.

    Returns:
        DKGOutput: The recovered DKG output.
        SessionParams: The common parameters of the recovered session.

    Raises:
        HostSeckeyError: If the host secret key is invalid, or if the key does not
            match the recovery data.
            (This can also occur if the recovery data is invalid.)
        RecoveryDataError: If recovery failed due to invalid recovery data.
    """
    if hostseckey is None:
        raise ValueError
    return recover(hostseckey, recovery_data)


def coordinator_recover(
    recovery_data: RecoveryData,
) -> tuple[DKGOutput, SessionParams]:
    """Recover the DKG output of the coordinator of a ChillDKG session.

    This function serves two different purposes:
    1. To recover from an exception in `coordinator_finalize`, after
       obtaining the recovery data from a participant. See
       `coordinator_finalize` for background.
    2. To reproduce the DKG outputs on a new device, e.g., to recover from a
       backup after data loss.

    Arguments:
        recovery_data: Recovery data from a successful session.

    Returns:
        DKGOutput: The recovered DKG output. Since the coordinator does not
            have a secret share, the DKG output will have the `secshare`
            field set to `None`.
        SessionParams: The common parameters of the recovered session.

    Raises:
        RecoveryDataError: If recovery failed due to invalid recovery data.
    """
    return recover(None, recovery_data)


class RecoveryDataError(ValueError):
    """Raised if the recovery data is invalid."""


###
### Recovery acknowledgment
###


def participant_recovery_ack_sign(
    hostseckey: bytes,
    recovery_data: RecoveryData,
    params: SessionParams,
    aux_rand: bytes,
) -> bytes:
    """Sign recovery data to create a recovery acknowledgment.

    This function allows a participant to create an explicit acknowledgment
    signature on the recovery data. This can be used for an optional
    acknowledgment round where participants acknowledge that they have
    successfully received the complete recovery data.

    Arguments:
        hostseckey: Participant's long-term host secret key (32 bytes).
        recovery_data: Recovery data from a successful session.
        params: Common session parameters.
        aux_rand: Auxiliary randomness (32 bytes). FRESH 32-byte randomness
            is optimal, but 16 random bytes or a counter padded to 32 bytes
            is acceptable (see BIP 340).

    Returns:
        bytes: Acknowledgment signature (64 bytes).

    Raises:
        HostSeckeyError: If the host secret key is invalid, or if it does not
            match any host public key.
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
        RecoveryDataError: If the recovery data is invalid or does not match
            the provided parameters.
    """
    hostpubkey = hostpubkey_gen(hostseckey)  # ValueError if len(hostseckey) != 32

    params_validate(params)
    (hostpubkeys, t) = params

    try:
        participant_id = hostpubkeys.index(hostpubkey)
    except ValueError as e:
        raise HostSeckeyError(
            "Host secret key does not match any host public key"
        ) from e
    if len(aux_rand) != 32:
        raise ValueError

    try:
        (t_rec, _, hostpubkeys_rec, _, _, _) = deserialize_recovery_data(recovery_data)
    except Exception as e:
        raise RecoveryDataError("Failed to deserialize recovery data") from e

    if t_rec != t or hostpubkeys_rec != hostpubkeys:
        raise RecoveryDataError(
            "Recovery data does not match the provided session parameters"
        )

    sig = recovery_ack_sign(hostseckey, participant_id, recovery_data, aux_rand)
    rmsg = RecoveryAckMsg(sig).to_bytes()
    return rmsg


def participant_recovery_acks_verify(
    recovery_data: RecoveryData, params: SessionParams, ack_sigs: list[bytes]
) -> None:
    """Verify recovery acknowledgment signatures from all participants.

    This function is used to ensure that all participants have
    received the recovery data before the threshold public key is used
    (e.g., before funds are sent to it).

    Arguments:
        recovery_data: Recovery data from a successful session.
        params: Common session parameters.
        ack_sigs: List of acknowledgment signatures (64 bytes each)
            from all participants, in the same order as `hostpubkeys`.

    Raises:
        InvalidHostPubkeyError: If `hostpubkeys` contains an invalid public key.
        DuplicateHostPubkeyError: If `hostpubkeys` contains duplicates.
        ThresholdOrCountError: If `1 <= t <= len(hostpubkeys) <= 2**32 - 1` does
            not hold.
        RecoveryDataError: If the recovery data is invalid or does not match
            the provided parameters.
        InvalidRecoveryAckError: If any recovery acknowledgment signature is
            invalid. Note that this does NOT mean the DKG failed
            (reaching this point implies the DKG itself was successful).
            It only means it cannot be confirmed that all participants
            have a copy of the recovery data.
    """
    params_validate(params)
    (hostpubkeys, t) = params

    if len(ack_sigs) != len(hostpubkeys):
        raise ValueError

    try:
        (t_rec, _, hostpubkeys_rec, _, _, _) = deserialize_recovery_data(recovery_data)
    except Exception as e:
        raise RecoveryDataError("Failed to deserialize recovery data") from e

    if t_rec != t or hostpubkeys_rec != hostpubkeys:
        raise RecoveryDataError(
            "Recovery data does not match the provided session parameters"
        )

    for i, sig in enumerate(ack_sigs):
        rmsg = RecoveryAckMsg.from_bytes(sig)
        msg = recovery_ack_message(recovery_data, i)
        valid = schnorr_verify(
            msg,
            # Dropping the sign byte from hostpubkeys[i] is okay because msg
            # commits on the full hostpubkeys[i]: it encodes all hostpubkeys
            # together with the id i.
            hostpubkeys[i][1:33],
            rmsg.sig,
        )
        if not valid:
            raise InvalidRecoveryAckError(i)


class InvalidRecoveryAckError(FaultyParticipantError):
    """Raised if a recovery acknowledgment signature is invalid.

    Attributes:
        participant_id (int): Identifier of the participant whose signature is
        invalid.
    """

    def __init__(self, participant_id: int, *args: Any):
        self.participant_id = participant_id
        super().__init__(participant_id, *args)
