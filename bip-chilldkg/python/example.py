#!/usr/bin/env python3

"""Example of a full ChillDKG session"""

import argparse
import asyncio
import pprint
import sys
from random import randint
from secrets import token_bytes as random_bytes

from chilldkg_ref import chilldkg
from chilldkg_ref.chilldkg import (
    DKGOutput,
    FaultyParticipantOrCoordinatorError,
    RecoveryData,
    SessionParams,
    UnknownFaultyParticipantOrCoordinatorError,
    coordinator_finalize,
    coordinator_investigate,
    coordinator_step1,
    hostpubkey_gen,
    params_hash,
    participant_finalize,
    participant_investigate,
    participant_step1,
    participant_step2,
)

#
# Network mocks to simulate full DKG sessions
#


class CoordinatorChannels:
    def __init__(self, n):
        self.n = n
        self.queues = []
        for i in range(n):
            self.queues += [asyncio.Queue()]

    def set_participant_queues(self, participant_queues):
        self.participant_queues = participant_queues

    def send_to(self, i, m):
        assert self.participant_queues is not None
        self.participant_queues[i].put_nowait(m)

    def send_all(self, m):
        assert self.participant_queues is not None
        for i in range(self.n):
            self.participant_queues[i].put_nowait(m)

    async def receive_from(self, i):
        item = await self.queues[i].get()
        return item


class ParticipantChannel:
    def __init__(self, coord_queue):
        self.queue = asyncio.Queue()
        self.coord_queue = coord_queue

    # Send m to coordinator
    def send(self, m):
        self.coord_queue.put_nowait(m)

    async def receive(self):
        item = await self.queue.get()
        return item


#
# Helper functions
#


def pphex(thing):
    """Pretty print an object with bytes as hex strings"""

    def hexlify(thing):
        if isinstance(thing, bytes):
            return thing.hex()
        if isinstance(thing, dict):
            return {k: hexlify(v) for k, v in thing.items()}
        if hasattr(thing, "_asdict"):  # NamedTuple
            return hexlify(thing._asdict())
        if isinstance(thing, list):
            return [hexlify(v) for v in thing]
        return thing

    pprint.pp(hexlify(thing))


#
# Protocol parties
#


async def participant(
    chan: ParticipantChannel,
    hostseckey: bytes,
    params: SessionParams,
    investigation_procedure: bool,
) -> tuple[DKGOutput, RecoveryData]:
    # TODO Top-level error handling
    random = random_bytes(32)
    state1, pmsg1 = participant_step1(hostseckey, params, random)

    chan.send(pmsg1)
    cmsg1 = await chan.receive()

    # Participants can implement an optional investigation procedure. This
    # allows the participant to determine which participant is faulty when an
    # `UnknownFaultyParticipantOrCoordinatorError` is raised. The investigation
    # procedure requires the participant to receive an extra "investigation
    # message" from the coordinator that contains necessary information.
    #
    # In this example, if the investigation procedure is enabled, the
    # participant expects the coordinator to send a investigation message.
    # Alternatively, an implementation of the participant can explicitly request
    # the investigation message only if participant_step2 fails.
    if investigation_procedure:
        cinv = await chan.receive()

    try:
        random = random_bytes(32)
        state2, eq_round1 = participant_step2(hostseckey, state1, cmsg1, random)
    except UnknownFaultyParticipantOrCoordinatorError as e:
        if investigation_procedure:
            participant_investigate(e, cinv)
        else:
            # If this participant does not implement the investigation
            # procedure, it cannot determine which party is faulty. Re-raise
            # UnknownFaultyPartyError in this case.
            raise

    chan.send(eq_round1)
    cmsg2 = await chan.receive()

    return participant_finalize(state2, cmsg2)


async def coordinator(
    chans: CoordinatorChannels, params: SessionParams, investigation_procedure: bool
) -> tuple[DKGOutput, RecoveryData]:
    (hostpubkeys, _) = params
    n = len(hostpubkeys)

    pmsgs1 = []
    for i in range(n):
        pmsgs1.append(await chans.receive_from(i))
    state, cmsg1 = coordinator_step1(pmsgs1, params)
    chans.send_all(cmsg1)

    # If the coordinator implements the investigation procedure and it is
    # enabled, it sends an extra message to the participants.
    if investigation_procedure:
        inv_msgs = coordinator_investigate(pmsgs1, params)
        for i in range(n):
            chans.send_to(i, inv_msgs[i])

    sigs = []
    for i in range(n):
        sigs += [await chans.receive_from(i)]
    cmsg2, dkg_output, recovery_data = coordinator_finalize(state, sigs)
    chans.send_all(cmsg2)

    return dkg_output, recovery_data


#
# DKG Session
#


# This is a dummy participant used to demonstrate the investigation procedure.
# It picks a random victim participant and sends an invalid share to it.
async def faulty_participant(
    chan: ParticipantChannel,
    hostseckey: bytes,
    params: SessionParams,
    participant_id: int,
):
    n = len(params.hostpubkeys)
    random = random_bytes(32)
    _, pmsg1 = participant_step1(hostseckey, params, random)
    pmsg1_parsed = chilldkg.ParticipantMsg1.from_bytes(pmsg1, t=params.t, n=n)

    assert len(pmsg1_parsed.enc_pmsg.enc_shares) == n
    # Pick random victim that is not this participant
    victim = (participant_id + randint(1, n - 1)) % n
    pmsg1_parsed.enc_pmsg.enc_shares[victim] += 17

    chan.send(pmsg1_parsed.to_bytes())


def simulate_chilldkg_full(
    hostseckeys: list[bytes], params: SessionParams, faulty_id: int | None
) -> list[tuple[DKGOutput, RecoveryData] | None]:
    n = len(hostseckeys)
    assert n == len(params.hostpubkeys)

    # For demonstration purposes, we enable the investigation pro if a participant is
    # faulty.
    investigation_procedure = faulty_id is not None

    async def session():
        coord_chans = CoordinatorChannels(n)
        participant_chans = [
            ParticipantChannel(coord_chans.queues[i]) for i in range(n)
        ]
        coord_chans.set_participant_queues(
            [participant_chans[i].queue for i in range(n)]
        )
        coroutines = [coordinator(coord_chans, params, investigation_procedure)] + [
            participant(
                participant_chans[i], hostseckeys[i], params, investigation_procedure
            )
            if i != faulty_id
            else faulty_participant(participant_chans[i], hostseckeys[i], params, i)
            for i in range(n)
        ]
        return await asyncio.gather(*coroutines)

    outputs = asyncio.run(session())
    return outputs


def main():
    parser = argparse.ArgumentParser(description="ChillDKG example")
    parser.add_argument(
        "--faulty-participant",
        action="store_true",
        help="When this flag is set, one random participant will send an invalid message, and the investigation procedure will be enabled for other participants and the coordinator.",
    )
    parser.add_argument(
        "t", nargs="?", type=int, default=2, help="Signing threshold [default = 2]"
    )
    parser.add_argument(
        "n", nargs="?", type=int, default=3, help="Number of participants [default = 3]"
    )
    args = parser.parse_args()
    t = args.t
    n = args.n
    if args.faulty_participant:
        faulty_id = randint(0, n - 1)
    else:
        faulty_id = None

    print("====== ChillDKG example session ======")
    print(f"Using n = {n} participants and a threshold of t = {t}.")
    if faulty_id is not None:
        print(f"Participant {faulty_id} is faulty.")
    print()

    # Generate common inputs for all participants and coordinator
    hostseckeys = [random_bytes(32) for _ in range(n)]
    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [hostpubkey_gen(hostseckeys[i])]
    params = SessionParams(hostpubkeys, t)

    print("=== Host secret keys ===")
    pphex(hostseckeys)
    print()

    print("=== Session parameters ===")
    pphex(params)
    print()
    print(f"Session parameters hash: {params_hash(params).hex()}")
    print()

    try:
        rets = simulate_chilldkg_full(hostseckeys, params, faulty_id)
    except FaultyParticipantOrCoordinatorError as e:
        print(
            f"A participant has failed and is blaming either participant {e.participant_id} or the coordinator."
        )
        # If the blamed participant is the faulty participant, exit with code 0.
        # Otherwise, re-raise the exception.
        if faulty_id == e.participant_id:
            return 0
        else:
            raise

    assert len(rets) == n + 1
    print("=== Coordinator's DKG output ===")
    dkg_output, _ = rets[0]
    pphex(dkg_output)
    print()

    for i in range(n):
        print(f"=== Participant {i}'s DKG output ===")
        dkg_output, _ = rets[i + 1]
        pphex(dkg_output)
        print()

    # Check that all RecoveryData of all parties is identical
    assert len({rets[i][1] for i in range(n + 1)}) == 1
    recovery_data = rets[0][1]
    print(f"=== Common recovery data ({len(recovery_data)} bytes) ===")
    print(recovery_data.hex())


if __name__ == "__main__":
    sys.exit(main())
