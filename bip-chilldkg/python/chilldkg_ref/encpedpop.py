from __future__ import annotations

from typing import NamedTuple, NoReturn

from secp256k1lab.ecdh import ecdh_libsecp256k1
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import GE, Scalar

from . import simplpedpop
from .util import (
    FaultyCoordinatorError,
    FaultyParticipantError,
    FaultyParticipantOrCoordinatorError,
    MsgParseError,
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
)

###
### Encryption
###


def ecdh(
    seckey: bytes, my_pubkey: bytes, their_pubkey: bytes, context: bytes, sending: bool
) -> Scalar:
    data = ecdh_libsecp256k1(seckey, their_pubkey)
    if sending:
        data += my_pubkey + their_pubkey
    else:
        data += their_pubkey + my_pubkey
    assert len(data) == 32 + 2 * 33
    data += context
    ret: Scalar = Scalar.from_bytes_wrapping(
        tagged_hash_bip_dkg("encpedpop ecdh", data)
    )
    return ret


def self_pad(symkey: bytes, nonce: bytes, context: bytes) -> Scalar:
    # Pad for symmetric encryption to ourselves
    pad: Scalar = Scalar.from_bytes_wrapping(
        tagged_hash_bip_dkg("encaps_multi self_pad", symkey + nonce + context)
    )
    return pad


def encaps_multi(
    secnonce: bytes,
    pubnonce: bytes,
    deckey: bytes,
    enckeys: list[bytes],
    context: bytes,
    participant_id: int,
) -> list[Scalar]:
    # This is effectively the "Hashed ElGamal" multi-recipient KEM described in
    # Section 5 of "Multi-recipient encryption, revisited" by Alexandre Pinto,
    # Bertram Poettering, Jacob C. N. Schuldt (AsiaCCS 2014). Its crucial
    # feature is to feed the index of the enckey to the hash function. The only
    # difference is that we feed also the pubnonce and context data into the
    # hash function.
    pads = []
    for i, enckey in enumerate(enckeys):
        context_ = i.to_bytes(4, byteorder="big") + context
        if i == participant_id:
            # We're encrypting to ourselves, so we use a symmetrically derived
            # pad to save the ECDH computation.
            pad = self_pad(symkey=deckey, nonce=pubnonce, context=context_)
        else:
            pad = ecdh(
                seckey=secnonce,
                my_pubkey=pubnonce,
                their_pubkey=enckey,
                context=context_,
                sending=True,
            )
        pads.append(pad)
    return pads


def encrypt_multi(
    secnonce: bytes,
    pubnonce: bytes,
    deckey: bytes,
    enckeys: list[bytes],
    context: bytes,
    participant_id: int,
    plaintexts: list[Scalar],
) -> list[Scalar]:
    pads = encaps_multi(secnonce, pubnonce, deckey, enckeys, context, participant_id)
    if len(plaintexts) != len(pads):
        raise ValueError
    ciphertexts = [plaintext + pad for plaintext, pad in zip(plaintexts, pads)]
    return ciphertexts


def decaps_multi(
    deckey: bytes,
    enckey: bytes,
    pubnonces: list[bytes],
    context: bytes,
    participant_id: int,
) -> list[Scalar]:
    context_ = participant_id.to_bytes(4, byteorder="big") + context
    pads = []
    for sender_id, pubnonce in enumerate(pubnonces):
        if sender_id == participant_id:
            pad = self_pad(symkey=deckey, nonce=pubnonce, context=context_)
        else:
            try:
                pad = ecdh(
                    seckey=deckey,
                    my_pubkey=enckey,
                    their_pubkey=pubnonce,
                    context=context_,
                    sending=False,
                )
            except ValueError as e:
                # Since deckey and enckey are well-formed, the error must have been
                # triggered by an invalid pubnonce.
                raise FaultyParticipantOrCoordinatorError(
                    sender_id, "invalid public nonce"
                ) from e
        pads.append(pad)
    return pads


def decrypt_sum(
    deckey: bytes,
    enckey: bytes,
    pubnonces: list[bytes],
    context: bytes,
    participant_id: int,
    sum_ciphertexts: Scalar,
) -> Scalar:
    if participant_id >= len(pubnonces):
        raise IndexError
    pads = decaps_multi(deckey, enckey, pubnonces, context, participant_id)
    sum_plaintexts: Scalar = sum_ciphertexts - Scalar.sum(*pads)
    return sum_plaintexts


###
### Messages
###


class ParticipantMsg(NamedTuple):
    simpl_pmsg: simplpedpop.ParticipantMsg
    pubnonce: bytes
    enc_shares: list[Scalar]

    @staticmethod
    def len_bytes(*, t: int, n: int) -> int:
        return simplpedpop.ParticipantMsg.len_bytes(t=t) + 33 + 32 * n

    @staticmethod
    def from_bytes(b: bytes, *, t: int, n: int) -> ParticipantMsg:
        if len(b) != ParticipantMsg.len_bytes(t=t, n=n):
            raise ValueError

        # Read simpl_pmsg
        simpl_pmsg_len = simplpedpop.ParticipantMsg.len_bytes(t=t)
        simpl_pmsg, rest = (
            simplpedpop.ParticipantMsg.from_bytes(b[:simpl_pmsg_len], t=t),
            b[simpl_pmsg_len:],
        )  # MsgParseError if invalid

        # Read pubnonce (33 bytes)
        pubnonce, rest = rest[:33], rest[33:]

        # Read enc_secshares (32*n bytes)
        try:
            enc_secshares = [
                Scalar.from_bytes_checked(rest[i : i + 32])  # ValueError if overflow
                for i in range(0, 32 * n, 32)
            ]
        except ValueError as e:
            raise MsgParseError("invalid encrypted secret share") from e

        return ParticipantMsg(simpl_pmsg, pubnonce, enc_secshares)

    def to_bytes(self) -> bytes:
        return (
            self.simpl_pmsg.to_bytes()
            + self.pubnonce
            + b"".join(share.to_bytes() for share in self.enc_shares)
        )


class CoordinatorMsg(NamedTuple):
    simpl_cmsg: simplpedpop.CoordinatorMsg
    pubnonces: list[bytes]

    @staticmethod
    def len_bytes(*, t: int, n: int) -> int:
        return simplpedpop.CoordinatorMsg.len_bytes(t=t, n=n) + 33 * n

    @staticmethod
    def from_bytes(b: bytes, *, t: int, n: int) -> CoordinatorMsg:
        if len(b) != CoordinatorMsg.len_bytes(t=t, n=n):
            raise ValueError

        # Read simpl_cmsg
        simpl_cmsg_len = simplpedpop.CoordinatorMsg.len_bytes(t=t, n=n)
        simpl_cmsg, rest = (
            simplpedpop.CoordinatorMsg.from_bytes(b[:simpl_cmsg_len], t=t, n=n),
            b[simpl_cmsg_len:],
        )  # MsgParseError if invalid

        # Read pubnonces (33*n bytes)
        pubnonces = [rest[i : i + 33] for i in range(0, 33 * n, 33)]

        return CoordinatorMsg(simpl_cmsg, pubnonces)

    def to_bytes(self) -> bytes:
        return self.simpl_cmsg.to_bytes() + b"".join(self.pubnonces)


class CoordinatorInvestigationMsg(NamedTuple):
    enc_partial_secshares: list[Scalar]
    partial_pubshares: list[GE]

    @staticmethod
    def len_bytes(*, n: int) -> int:
        return simplpedpop.CoordinatorInvestigationMsg.len_bytes(n=n) + 32 * n

    @staticmethod
    def from_bytes(b: bytes, *, n: int) -> CoordinatorInvestigationMsg:
        if len(b) != CoordinatorInvestigationMsg.len_bytes(n=n):
            raise ValueError

        # Read enc_partial_secshares (32*n bytes)
        try:
            enc_partial_secshares, rest = (
                [
                    Scalar.from_bytes_checked(b[i : i + 32])
                    for i in range(0, 32 * n, 32)
                ],  # ValueError if overflow
                b[32 * n :],
            )
        except ValueError as e:
            raise MsgParseError("invalid encrypted partial secshare") from e

        # Read partial_pubshares (33*n bytes)
        try:
            partial_pubshares = [
                GE.from_bytes_compressed_with_infinity(rest[i : i + 33])
                for i in range(0, 33 * n, 33)
            ]
        except ValueError as e:
            raise MsgParseError("invalid partial pubshare") from e

        return CoordinatorInvestigationMsg(enc_partial_secshares, partial_pubshares)

    def to_bytes(self) -> bytes:
        secshares_bytes = b"".join(
            share.to_bytes() for share in self.enc_partial_secshares
        )
        pubshares_bytes = b"".join(
            P.to_bytes_compressed_with_infinity() for P in self.partial_pubshares
        )
        return secshares_bytes + pubshares_bytes


###
### Participant
###


class ParticipantState(NamedTuple):
    simpl_state: simplpedpop.ParticipantState
    pubnonce: bytes
    enckeys: list[bytes]
    participant_id: int


class ParticipantInvestigationData(NamedTuple):
    simpl_bstate: simplpedpop.ParticipantInvestigationData
    enc_secshare: Scalar
    pads: list[Scalar]


def serialize_enc_context(t: int, enckeys: list[bytes]) -> bytes:
    return t.to_bytes(4, byteorder="big") + b"".join(enckeys)


def participant_step1(
    seed: bytes,
    deckey: bytes,
    enckeys: list[bytes],
    t: int,
    participant_id: int,
    random: bytes,
) -> tuple[ParticipantState, bytes]:
    if t >= 2 ** (4 * 8):
        raise ValueError
    if len(random) != 32:
        raise ValueError
    n = len(enckeys)

    # Derive an encryption nonce and a seed for SimplPedPop.
    #
    # SimplPedPop will use its seed to derive the secret shares, which we will
    # encrypt using the encryption nonce. That means that all entropy used in
    # the derivation of simpl_seed should also be in the derivation of the
    # pubnonce, to ensure that we never encrypt different secret shares with the
    # same encryption pads. The foolproof way to achieve this is to simply
    # derive the nonce from simpl_seed.
    enc_context = serialize_enc_context(t, enckeys)
    simpl_seed = tagged_hash_bip_dkg("encpedpop seed", seed + random + enc_context)
    simpl_aux_rand = tagged_hash_bip_dkg("simplpedpop aux", simpl_seed)
    secnonce = tagged_hash_bip_dkg("encpedpop secnonce", simpl_seed)
    pubnonce = pubkey_gen_plain(secnonce)

    simpl_state, simpl_pmsg, shares = simplpedpop.participant_step1(
        simpl_seed, t, n, participant_id, simpl_aux_rand
    )
    assert len(shares) == n

    enc_shares = encrypt_multi(
        secnonce, pubnonce, deckey, enckeys, enc_context, participant_id, shares
    )
    simpl_pmsg_parsed = simplpedpop.ParticipantMsg.from_bytes(simpl_pmsg, t=t)

    pmsg = ParticipantMsg(simpl_pmsg_parsed, pubnonce, enc_shares).to_bytes()
    state = ParticipantState(simpl_state, pubnonce, enckeys, participant_id)
    return state, pmsg


def participant_step2(
    state: ParticipantState,
    deckey: bytes,
    cmsg: bytes,
    enc_secshare: Scalar,
) -> tuple[simplpedpop.DKGOutput, bytes]:
    simpl_state, pubnonce, enckeys, participant_id = state
    try:
        cmsg_parsed = CoordinatorMsg.from_bytes(cmsg, t=simpl_state.t, n=len(enckeys))
    except MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    simpl_cmsg, pubnonces = cmsg_parsed

    reported_pubnonce = pubnonces[participant_id]
    if reported_pubnonce != pubnonce:
        raise FaultyCoordinatorError("Coordinator replied with wrong pubnonce")

    enc_context = serialize_enc_context(simpl_state.t, enckeys)
    pads = decaps_multi(
        deckey, enckeys[participant_id], pubnonces, enc_context, participant_id
    )
    secshare = enc_secshare - Scalar.sum(*pads)

    try:
        dkg_output, eq_input = simplpedpop.participant_step2(
            simpl_state, simpl_cmsg.to_bytes(), secshare
        )
    except UnknownFaultyParticipantOrCoordinatorError as e:
        assert isinstance(e.inv_data, simplpedpop.ParticipantInvestigationData)
        # Translate simplpedpop.ParticipantInvestigationData into our own
        # encpedpop.ParticipantInvestigationData.
        inv_data = ParticipantInvestigationData(e.inv_data, enc_secshare, pads)
        raise UnknownFaultyParticipantOrCoordinatorError(inv_data, *e.args) from e

    eq_input += b"".join(enckeys) + b"".join(pubnonces)
    return dkg_output, eq_input


def participant_investigate(
    error: UnknownFaultyParticipantOrCoordinatorError,
    cinv: bytes,
) -> NoReturn:
    simpl_inv_data, enc_secshare, pads = error.inv_data
    try:
        cinv_parsed = CoordinatorInvestigationMsg.from_bytes(cinv, n=simpl_inv_data.n)
    except MsgParseError as e:
        raise FaultyCoordinatorError(*e.args) from e
    enc_partial_secshares, partial_pubshares = cinv_parsed
    partial_secshares = [
        enc_partial_secshare - pad
        for enc_partial_secshare, pad in zip(enc_partial_secshares, pads)
    ]

    simpl_cinv = simplpedpop.CoordinatorInvestigationMsg(partial_pubshares)
    try:
        simplpedpop.participant_investigate(
            UnknownFaultyParticipantOrCoordinatorError(simpl_inv_data),
            simpl_cinv.to_bytes(),
            partial_secshares,
        )
    except simplpedpop.SecshareSumError as e:
        # The secshare is not equal to the sum of the partial secshares in the
        # investigation message. Since the encryption is additively homomorphic,
        # this can only happen if the sum of the *encrypted* secshare is not
        # equal to the sum of the encrypted partial secshares, which is the
        # coordinator's fault.
        assert Scalar.sum(*enc_partial_secshares) != enc_secshare
        raise FaultyCoordinatorError(
            "Sum of encrypted partial secshares not equal to encrypted secshare"
        ) from e


###
### Coordinator
###


def coordinator_step(
    pmsgs: list[bytes],
    t: int,
    enckeys: list[bytes],
) -> tuple[bytes, simplpedpop.DKGOutput, bytes, list[Scalar]]:
    n = len(enckeys)
    if n != len(pmsgs):
        raise ValueError

    pmsgs_parsed = []
    for i, pmsg in enumerate(pmsgs):
        try:
            parsed = ParticipantMsg.from_bytes(pmsg, t=t, n=n)
        except MsgParseError as e:
            raise FaultyParticipantError(i, *e.args) from e
        pmsgs_parsed.append(parsed)
    simpl_cmsg, dkg_output, eq_input = simplpedpop.coordinator_step(
        pmsgs=[pmsg.simpl_pmsg.to_bytes() for pmsg in pmsgs_parsed], t=t, n=n
    )
    simpl_cmsg_parsed = simplpedpop.CoordinatorMsg.from_bytes(simpl_cmsg, t=t, n=n)
    pubnonces = [pmsg.pubnonce for pmsg in pmsgs_parsed]
    enc_secshares = [
        Scalar.sum(*([pmsg.enc_shares[i] for pmsg in pmsgs_parsed])) for i in range(n)
    ]
    eq_input += b"".join(enckeys) + b"".join(pubnonces)

    # In ChillDKG, the coordinator needs to broadcast the entire enc_secshares
    # array to all participants. But in pure EncPedPop, the coordinator needs to
    # send to each participant i only their entry enc_secshares[i].
    #
    # Since broadcasting the entire array is not necessary, we don't include it
    # in encpedpop.CoordinatorMsg, but only return it as a side output, so that
    # chilldkg.coordinator_step can pick it up. Implementations of pure
    # EncPedPop will need to decide how to transmit enc_secshares[i] to
    # participant i for participant_step2(); we leave this unspecified.
    return (
        CoordinatorMsg(simpl_cmsg_parsed, pubnonces).to_bytes(),
        dkg_output,
        eq_input,
        enc_secshares,
    )


def coordinator_investigate(pmsgs: list[bytes], t: int) -> list[bytes]:
    n = len(pmsgs)
    pmsgs_parsed = [ParticipantMsg.from_bytes(pmsg, t=t, n=n) for pmsg in pmsgs]
    simpl_pmsgs = [pmsg.simpl_pmsg.to_bytes() for pmsg in pmsgs_parsed]

    all_enc_partial_secshares = [
        [pmsg.enc_shares[i] for pmsg in pmsgs_parsed] for i in range(n)
    ]
    simpl_cinvs = simplpedpop.coordinator_investigate(simpl_pmsgs, t)
    simpl_cinvs_parsed = [
        simplpedpop.CoordinatorInvestigationMsg.from_bytes(simpl_cinv, n=n)
        for simpl_cinv in simpl_cinvs
    ]
    cinvs = [
        CoordinatorInvestigationMsg(
            all_enc_partial_secshares[i], simpl_cinvs_parsed[i].partial_pubshares
        ).to_bytes()
        for i in range(n)
    ]
    return cinvs
