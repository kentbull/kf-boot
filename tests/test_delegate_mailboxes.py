"""An onboarded account allocates a hosted mailbox for an identifier it delegated."""
from __future__ import annotations

from keri.app import habbing
from keri.core import Diger, Number
from keri.core.coring import NumDex
from keri.core.eventing import SealEvent
from keri.core.serdering import SerderKERI

from kfboot.basing import BOOT_OPERATION_DELEGATE_MAILBOX, BOOT_OPERATION_SUCCEEDED

from .support import (
    assert_reply_frame,
    build_exn,
    post_cesr,
    run_boot_operations,
    split_cesr_stream,
)


def post_stream(contract, stream):
    """Post each event of a KEL stream to the account surface, as the wallet does."""
    buf = bytearray(stream)
    for serder in split_cesr_stream(bytes(stream)):
        del buf[:serder.size]
        end = 0
        while end < len(buf) and buf[end] != 0x7B:
            end += 1
        response = post_cesr(contract, "/account", bytes(serder.raw) + bytes(buf[:end]))
        assert response.status_code == 204, (serder.ilk, serder.pre, serder.sn, response.text)
        del buf[:end]


def delegate_of(account, name="program"):
    """Return a separate wallet's identifier delegated and anchored by ``account``."""
    hby = habbing.Habery(name=f"{name}-wallet", temp=True)
    hby.psr.parse(ims=bytearray(account.replay()))
    delegate = hby.makeHab(name=name, delpre=account.pre)
    dip = delegate.kever.serder if delegate.kever else None
    if dip is None:  # escrowed until its anchor arrives
        dip = hby.db.evts.get(keys=(delegate.pre, hby.db.kels.getLast(keys=delegate.pre, on=0)))
    anchor = SerderKERI(raw=account.interact(data=[SealEvent(i=delegate.pre, s=dip.snh, d=dip.said)._asdict()]))
    hby.psr.parse(ims=bytearray(account.replay()))
    # As the wallet records it, so the replayed inception carries its anchor's source seal.
    hby.db.aess.pin(keys=(delegate.pre, dip.said),
                    val=(Number(num=anchor.sn, code=NumDex.Huge), Diger(qb64=anchor.said)))
    hby.kvy.processEscrows()
    return hby, delegate


def mailbox_request(contract, account, aid):
    return post_cesr(contract, "/account", build_exn(account, route="/account/mailboxes",
                                                    payload={"account_aid": account.pre, "aid": aid}))


def test_account_allocates_mailbox_for_its_delegate_and_deletion_removes_it(onboarded_bundle):
    contract, account = onboarded_bundle["contract"], onboarded_bundle["account"]
    hby, program = delegate_of(account)
    try:
        assert program.kever.delpre == account.pre

        # The delegation is verified from accepted key state, not taken from the request.
        refused = mailbox_request(contract, account, program.pre)
        assert refused.status_code == 409 and "key event log" in refused.text
        post_stream(contract, program.replay())
        assert contract.ctx.habery.kevers[program.pre].delpre == account.pre

        response = mailbox_request(contract, account, program.pre)
        _, reply = assert_reply_frame(contract, response, route="/account/mailboxes")
        operation = reply.ked["a"]["operation"]
        assert reply.ked["a"]["aid"] == program.pre
        assert operation["kind"] == BOOT_OPERATION_DELEGATE_MAILBOX
        assert operation["subject"] == f"mailbox:{program.pre}"

        run_boot_operations(contract)
        done = contract.ctx.store.getBootOperation(operation["operation_id"])
        assert done.state == BOOT_OPERATION_SUCCEEDED, done.last_error
        mailbox = done.result["mailbox"]
        record = contract.ctx.store.getResource("mailbox", mailbox["eid"])
        assert (record.cid, record.principal) == (program.pre, account.pre)
        assert mailbox["oobis"] == record.oobis and mailbox["url"] == record.url
        creators = [boot for boot in contract.ctx.witness_boots.values() if program.pre in boot.create_cids]
        assert len(creators) == 1  # one witness-service slot, bound to the delegate's AID

        # The account reads its own operation; a retry returns the same mailbox.
        status = post_cesr(contract, "/account", build_exn(account, route="/operations/status",
                                                           payload={"operation_id": done.operation_id}))
        _, status_reply = assert_reply_frame(contract, status, route="/operations/status")
        assert status_reply.ked["a"]["operation"]["result"]["mailbox"]["eid"] == mailbox["eid"]
        again = mailbox_request(contract, account, program.pre)
        _, again_reply = assert_reply_frame(contract, again, route="/account/mailboxes")
        run_boot_operations(contract)
        retried = contract.ctx.store.getBootOperation(again_reply.ked["a"]["operation"]["operation_id"])
        assert retried.result["mailbox"]["eid"] == mailbox["eid"]
        assert sum(boot.create_calls for boot in creators) == 1

        # Deleting the account removes the hosted mailbox with its other resources.
        deleted = post_cesr(contract, "/account", build_exn(account, route="/account/delete",
                                                            payload={"account_aid": account.pre}))
        assert_reply_frame(contract, deleted, route="/account/delete")
        run_boot_operations(contract)
        assert contract.ctx.store.getResource("mailbox", mailbox["eid"]) is None
        assert mailbox["eid"] in creators[0].delete_calls
    finally:
        hby.close(clear=True)


def test_account_cannot_allocate_mailbox_for_itself_or_an_unrelated_identifier(onboarded_bundle):
    contract, account = onboarded_bundle["contract"], onboarded_bundle["account"]
    with habbing.openHab(name="stranger", temp=True) as (_, stranger):
        post_stream(contract, stranger.replay())
        for aid in (account.pre, stranger.pre):
            response = mailbox_request(contract, account, aid)
            assert response.status_code == 403, response.text
            assert "this account delegated" in response.text
    assert not contract.ctx.store.listResourcesForAccount(kind="mailbox", account_aid=account.pre)
