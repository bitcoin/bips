#!/usr/bin/env python3

"""Example of a full FROST signing session."""

from typing import List, Tuple
import asyncio
import argparse
import secrets

# Import frost_ref first to set up secp256k1lab path
from frost_ref import (
    nonce_gen,
    nonce_agg,
    sign,
    partial_sig_agg,
    partial_sig_verify,
    SignersContext,
    SessionContext,
    PlainPk,
)
from frost_ref.signing import (
    thresh_pubkey_and_tweak,
    get_xonly_pk,
    partial_sig_verify_internal,
)

from secp256k1lab.bip340 import schnorr_verify
from trusted_dealer import trusted_dealer_keygen


#
# Network mocks to simulate full FROST signing sessions
#


class CoordinatorChannels:
    def __init__(self, n):
        self.n = n
        self.queues = [asyncio.Queue() for _ in range(n)]
        self.participant_queues = None

    def set_participant_queues(self, participant_queues):
        self.participant_queues = participant_queues

    def send_to(self, i, m):
        assert self.participant_queues is not None
        self.participant_queues[i].put_nowait(m)

    def send_all(self, m):
        assert self.participant_queues is not None
        for i in range(self.n):
            self.participant_queues[i].put_nowait(m)

    async def receive_from(self, i: int) -> bytes:
        return await self.queues[i].get()


class ParticipantChannel:
    def __init__(self, coord_queue):
        self.queue = asyncio.Queue()
        self.coord_queue = coord_queue

    def send(self, m):
        self.coord_queue.put_nowait(m)

    async def receive(self):
        return await self.queue.get()


#
# Helper functions
#


def generate_frost_keys(
    n: int, t: int
) -> Tuple[PlainPk, List[int], List[bytes], List[PlainPk]]:
    """Generate t-of-n FROST keys using trusted dealer.

    Returns:
        thresh_pk: Threshold public key (33-byte compressed)
        ids: List of signer IDs (0-indexed: 0, 1, ..., n-1)
        secshares: List of secret shares (32-byte scalars)
        pubshares: List of public shares (33-byte compressed)
    """
    thresh_pk, secshares, pubshares = trusted_dealer_keygen(
        secrets.token_bytes(32), n, t
    )

    assert len(secshares) == n
    ids = list(range(len(secshares)))  # ids are 0..n-1

    return thresh_pk, ids, secshares, pubshares


#
# Protocol parties
#


async def participant(
    chan: ParticipantChannel,
    secshare: bytes,
    pubshare: PlainPk,
    my_id: int,
    signers_ctx: SignersContext,
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
) -> Tuple[bytes, bytes]:
    """
    Participant in FROST signing protocol.

    Returns:
        (psig, final_sig): Partial signature and final BIP340 signature
    """
    # Get tweaked threshold pubkey
    tweak_ctx = thresh_pubkey_and_tweak(signers_ctx.thresh_pk, tweaks, is_xonly)
    tweaked_thresh_pk = get_xonly_pk(tweak_ctx)

    # Round 1: Nonce generation
    secnonce, pubnonce = nonce_gen(secshare, pubshare, tweaked_thresh_pk, msg, None)
    chan.send(pubnonce)
    aggnonce = await chan.receive()

    # Round 2: Signing
    session_ctx = SessionContext(aggnonce, signers_ctx, tweaks, is_xonly, msg)
    psig = sign(secnonce, secshare, my_id, session_ctx)
    assert partial_sig_verify_internal(psig, my_id, pubnonce, pubshare, session_ctx), (
        "Partial signature verification failed"
    )
    chan.send(psig)

    # Receive final signature
    final_sig = await chan.receive()
    return (psig, final_sig)


async def coordinator(
    chans: CoordinatorChannels,
    signers_ctx: SignersContext,
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
) -> bytes:
    """
    Coordinator in FROST signing protocol.

    Returns:
        final_sig: Final BIP340 signature (64 bytes)
    """
    # Determine the signers
    signer_ids = signers_ctx.ids
    num_signers = len(signer_ids)

    # Round 1: Collect pubnonces
    pubnonces = []
    for i in range(num_signers):
        pubnonce = await chans.receive_from(i)
        pubnonces.append(pubnonce)

    # Aggregate nonces
    aggnonce = nonce_agg(pubnonces, signer_ids)
    chans.send_all(aggnonce)

    # Round 2: Collect partial signatures
    session_ctx = SessionContext(aggnonce, signers_ctx, tweaks, is_xonly, msg)
    psigs = []
    for i in range(num_signers):
        psig = await chans.receive_from(i)
        assert partial_sig_verify(
            psig, pubnonces, signers_ctx, tweaks, is_xonly, msg, i
        ), f"Partial signature verification failed for singer {i}"
        psigs.append(psig)

    # Aggregate partial signatures
    final_sig = partial_sig_agg(psigs, signer_ids, session_ctx)
    chans.send_all(final_sig)

    return final_sig


#
# Signing Session
#


def simulate_frost_signing(
    secshares: List[bytes],
    signers_ctx: SignersContext,
    msg: bytes,
    tweaks: List[bytes],
    is_xonly: List[bool],
) -> Tuple[bytes, List[bytes]]:
    """Run a full FROST signing session.

    Returns:
        (final_sig, psigs): Final signature and list of partial signatures
    """
    # Extract signer set from signers_ctx
    signer_ids = signers_ctx.ids
    pubshares = signers_ctx.pubshares
    num_signers = len(signer_ids)

    async def session():
        # Set up channels
        coord_chans = CoordinatorChannels(num_signers)
        participant_chans = [
            ParticipantChannel(coord_chans.queues[i]) for i in range(num_signers)
        ]
        coord_chans.set_participant_queues(
            [participant_chans[i].queue for i in range(num_signers)]
        )

        # Create coroutines
        coroutines = [coordinator(coord_chans, signers_ctx, tweaks, is_xonly, msg)] + [
            participant(
                participant_chans[i],
                secshares[i],
                pubshares[i],
                signer_ids[i],
                signers_ctx,
                tweaks,
                is_xonly,
                msg,
            )
            for i in range(num_signers)
        ]

        return await asyncio.gather(*coroutines)

    results = asyncio.run(session())
    final_sig = results[0]
    psigs = [r[0] for r in results[1:]]  # Extract psigs from participant results
    return final_sig, psigs


def main():
    parser = argparse.ArgumentParser(description="FROST Signing example")
    parser.add_argument(
        "t", nargs="?", type=int, default=2, help="Threshold [default=2]"
    )
    parser.add_argument(
        "n", nargs="?", type=int, default=3, help="Participants [default=3]"
    )
    args = parser.parse_args()

    t, n = args.t, args.n
    assert 2 <= t <= n, "Threshold t must satisfy 2 <= t <= n"

    print("====== FROST Signing example session ======")
    print(f"Using n = {n} participants and a threshold of t = {t}.")
    print()

    # 1. Generate FROST keys
    thresh_pk, all_ids, all_secshares, all_pubshares = generate_frost_keys(n, t)

    print("=== Key Configuration ===")
    print(f"Threshold public key: {thresh_pk.hex()}")
    print()
    print("=== Public shares ===")
    for i, pubshare in enumerate(all_pubshares):
        print(f"  Participant {all_ids[i]}: {pubshare.hex()}")
    print()

    # 2. Select first t signers
    signer_indices = list(range(t))
    signer_ids = [all_ids[i] for i in signer_indices]
    signer_secshares = [all_secshares[i] for i in signer_indices]
    signer_pubshares = [all_pubshares[i] for i in signer_indices]

    # 3. Initialize the signers context
    print("=== Signing Set ===")
    print(f"Selected signers: {signer_ids}")
    print()
    signers_ctx = SignersContext(n, t, signer_ids, signer_pubshares, thresh_pk)

    # 4. Create message and tweaks
    msg = secrets.token_bytes(32)

    # Apply both plain (BIP32-style) and xonly (BIP341-style) tweaks
    tweaks = [secrets.token_bytes(32), secrets.token_bytes(32)]
    is_xonly = [False, True]  # First: plain (BIP32), Second: xonly (BIP341)

    tweak_ctx = thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly)
    tweaked_thresh_pk = get_xonly_pk(tweak_ctx)

    print("=== Message and Tweaks ===")
    print(f"Message: {msg.hex()}")
    print(f"Tweak 1 (plain/BIP32): {tweaks[0].hex()}")
    print(f"Tweak 2 (xonly/BIP341): {tweaks[1].hex()}")
    print(f"Tweaked threshold public key: {tweaked_thresh_pk.hex()}")
    print()

    # 5. Run signing protocol
    final_sig, psigs = simulate_frost_signing(
        signer_secshares,
        signers_ctx,
        msg,
        tweaks,
        is_xonly,
    )

    print("=== Participants Partial Signatures ===")
    for i, psig in enumerate(psigs):
        print(f"  Participant {signer_ids[i]}: {psig.hex()}")
    print()

    print("=== Final Signature ===")
    print(f"BIP340 signature: {final_sig.hex()}")
    print()

    # 6. Verify signature
    assert schnorr_verify(msg, tweaked_thresh_pk, final_sig)
    print("=== Verification ===")
    print("Signature verified successfully!")


if __name__ == "__main__":
    main()
