"""Provision real Registrar/Observer accounts over HTTP with signed provider requests."""
import ssl
import time
from contextlib import ExitStack, closing, contextmanager
from dataclasses import replace
from types import SimpleNamespace

from falcon import testing
from hio.base import doing
from hio.core import http, tcp
from keri import Vrsn_2_0
from keri.app import habbing, httping
from keri.core import Parser
from keri.peer.exchanging import verifyAttachments
from kfobserver.core.evidence import Context as ObserverContext
from kfregistrar.core.serving import makeContext

from kfboot.app import create_app
from kfboot.basing import (
    ACCOUNT_STATE_EXPIRED,
    ACCOUNT_STATE_ONBOARDED,
    BOOT_OPERATION_FAILED,
    BOOT_OPERATION_PENDING,
    BOOT_OPERATION_SUCCEEDED,
    SESSION_STATE_CANCELLED,
    AccountRecord,
    SessionRecord,
)
from kfboot.boot_client import BootError, HioBootClient
from kfboot.config import RegistryBackend
from kfboot.operating import BootOperationDoer, BootOperationProcessor

from .support import assert_reply_frame, build_exn, make_config, post_cesr, register_aid


@contextmanager
def registry_lab(tmp_path):
    """Own separate key stores, actual private APIs and one cooperative scheduler."""
    with ExitStack() as stack:
        wallets = stack.enter_context(habbing.openHby(name="service-wallets", version=Vrsn_2_0))
        registrar_hby = stack.enter_context(habbing.openHby(name="service-registrar", version=Vrsn_2_0))
        observer_hby = stack.enter_context(habbing.openHby(name="service-observer", version=Vrsn_2_0))
        observer_hab = observer_hby.makeHab("observer")
        registrar = stack.enter_context(closing(makeContext(registrar_hby, observers=[observer_hab.pre])))
        observer = stack.enter_context(closing(ObserverContext(observer_hby, hab=observer_hab)))
        services = {"registrar": registrar, "observer": observer}
        ca_pem = ssl.DER_cert_to_PEM_cert(ssl.create_default_context().get_ca_certs(binary_form=True)[0])
        backends, servers = {}, []
        for kind, service in services.items():
            servant = tcp.Server(ha=("127.0.0.1", 0))
            stack.callback(servant.close)
            assert servant.reopen()
            servant.eha = servant.ha  # Advertise the port selected by the OS, not the input port zero.
            server = http.Server(servant=servant, ha=servant.ha, app=service.internalApp)
            stack.callback(server.close)
            servers.append(http.ServerDoer(server=server))
            backends[kind] = RegistryBackend(
                boot_url=f"http://127.0.0.1:{server.servant.ha[1]}",
                public_url=f"https://{kind}.example", service_aid=service.hab.pre, ca_pem=ca_pem)
        app, ctx = create_app(make_config(tmp_path, **backends), temp=True)
        stack.callback(ctx.close, clear=True)
        client = testing.TestClient(app)
        client.ctx = ctx
        clienter = httping.Clienter()
        boots = {kind: HioBootClient(backend.boot_url, clienter=clienter, timeout=2)
                 for kind, backend in backends.items()}
        processor = BootOperationProcessor(provisioner=ctx.exchanger.provisioner, registry_clienter=clienter)
        worker = BootOperationDoer(store=ctx.store, registry_boots=boots, clienter=clienter,
                                  processor=processor, interval=.01)
        ctx.exchanger.provisioner.configureCleanupBootClients(
            witness_boots={}, watcher_boot=None, registry_clienter=clienter)
        doist = doing.Doist(tock=.01)
        deeds = doist.enter(doers=[*servers, worker])
        stack.callback(doist.exit, deeds=deeds)
        yield SimpleNamespace(wallets=wallets, ctx=ctx, client=client, services=services,
                              backends=backends, doist=doist, deeds=deeds)


def pump(lab, complete):
    """Advance actual sockets until one explicit condition or a short wall deadline."""
    deadline = time.monotonic() + 5
    while not complete():
        assert time.monotonic() < deadline, "registry operation did not finish"
        lab.doist.recur(deeds=lab.deeds)
        time.sleep(.001)


def signed_reply(lab, hab, route, payload):
    """Verify the provider's actual reply attachments with the ordinary KERI owner."""
    response = post_cesr(lab.client, "/account", build_exn(hab, route=route, payload=payload))
    _, reply = assert_reply_frame(lab.client, response, route=route)
    hab.psr.parse(ims=bytearray(lab.ctx.exchanger.hostKELReplay()))
    ims = bytearray(response.content)
    parser = Parser(version=Vrsn_2_0)
    while ims:
        dom = parser.parseOneBare(ims=ims, processive=False)
    groups, cigars, seals, invalid, missing = verifyAttachments(
        lab.wallets, dom.serder, tsgs=dom.tsgs, cigars=dom.cigars, sourceSeals=dom.ssts)
    assert not invalid and not missing and (groups or cigars or seals)
    assert dom.serder.said == reply.said
    return reply.ked["a"]


def test_account_services_activate_and_clean_up_real_backends(tmp_path):
    """Two independent accounts, signed capabilities, expiry during PUT, and final deletion."""
    with registry_lab(tmp_path) as lab:
        first, second = (lab.wallets.makeHab(name) for name in ("first", "second"))
        for hab in (first, second):
            register_aid(lab.client, "/account", hab)
            lab.ctx.store.saveAccount(AccountRecord(account_aid=hab.pre, status=ACCOUNT_STATE_ONBOARDED,
                                                    tier="trial", witness_profile_code="1-of-1"))
        # Authentication does not permit one account to enroll another account's identity.
        refused = post_cesr(lab.client, "/account", build_exn(first, route="/account/services",
                                                             payload={"account_aid": second.pre}))
        assert refused.status_code == 401
        assert first.pre not in lab.services["registrar"].publishers

        started = signed_reply(lab, first, "/account/services", {})
        opid = started["operation"]["operation_id"]
        # Cleaning an older onboarding session must not cancel this account's new activation.
        old = SessionRecord(session_id="older-session", account_aid=first.pre, state=SESSION_STATE_CANCELLED)
        cleanup = lab.ctx.exchanger.provisioner.teardownSessionResourcesDo(
            session=old, account=lab.ctx.store.getAccount(first.pre), tymth=lab.doist.tymen())
        assert list(cleanup) == []
        assert lab.ctx.store.getBootOperation(opid).state == BOOT_OPERATION_PENDING
        pump(lab, lambda: lab.ctx.store.getBootOperation(opid).state == BOOT_OPERATION_SUCCEEDED)
        status = signed_reply(lab, first, "/operations/status", {"operation_id": opid})
        capabilities = status["operation"]["result"]["services"]
        for kind, role in (("registrar", "publisher"), ("observer", "reader")):
            backend = lab.backends[kind]
            assert capabilities[kind] == {"aid": first.pre, "roles": [role], "service": backend.service_aid,
                                          "url": backend.public_url, "ca_pem": backend.ca_pem}
            assert lab.ctx.store.getResource(kind, first.pre).status == "active"
        assert first.pre in lab.services["registrar"].publishers
        assert first.pre in lab.services["observer"].readers

        # Stop after the second account's PUT has taken effect but before its response is consumed.
        started = signed_reply(lab, second, "/account/services", {})
        second_op = started["operation"]["operation_id"]
        pump(lab, lambda: second.pre in lab.services["registrar"].publishers)
        account = lab.ctx.store.getAccount(second.pre)
        account.status = ACCOUNT_STATE_EXPIRED
        lab.ctx.store.saveAccount(account)
        cleanup = lab.ctx.exchanger.provisioner.teardownAccountResourcesDo(
            account_aid=second.pre, account=account, tymth=lab.doist.tymen())
        try:
            next(cleanup)
        except BootError as error:
            assert error.status_code == 425  # Cleanup waits for the running PUT's terminal result.
        else:
            raise AssertionError("cleanup did not defer the in-flight activation")
        pump(lab, lambda: lab.ctx.store.getBootOperation(second_op).state == BOOT_OPERATION_FAILED)

        # Retained resource coordinates permit cleanup even after configuration is removed.
        lab.ctx.exchanger.ctx.config = replace(lab.ctx.config, registrar=None, observer=None)
        cleanup = lab.ctx.exchanger.provisioner.teardownAccountResourcesDo(
            account_aid=second.pre, account=account, tymth=lab.doist.tymen())
        complete = False
        def clean():
            nonlocal complete
            if not complete:
                try:
                    next(cleanup)
                except StopIteration:
                    complete = True
            return complete
        pump(lab, clean)
        assert lab.ctx.store.getResource("registrar", second.pre) is None
        assert second.pre not in lab.services["registrar"].publishers
        assert first.pre in lab.services["registrar"].publishers
        assert first.pre in lab.services["observer"].readers

        # Normal signed account deletion revokes both grants, preserving the fixed source observer.
        deleted = signed_reply(lab, first, "/account/delete", {})
        delete_op = deleted["operation"]["operation_id"]
        pump(lab, lambda: lab.ctx.store.getBootOperation(delete_op).state == BOOT_OPERATION_SUCCEEDED)
        assert lab.ctx.store.getAccount(first.pre) is None
        assert first.pre not in lab.services["registrar"].publishers
        assert first.pre not in lab.services["observer"].readers
        assert lab.services["observer"].hab.pre in lab.services["registrar"].observers
