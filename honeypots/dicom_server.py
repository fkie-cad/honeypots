"""
//  -------------------------------------------------------------
//  author        jstucke
//  project       qeeqbox/honeypots
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
"""
from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING
from unittest.mock import patch

from pynetdicom import ae, ALL_TRANSFER_SYNTAXES, AllStoragePresentationContexts, evt
from pynetdicom._handlers import standard_dimse_recv_handler, standard_pdu_recv_handler
from pynetdicom.dul import DULServiceProvider
from pynetdicom.sop_class import Verification

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)

if TYPE_CHECKING:
    from socket import socket

SUCCESS = 0x0000


class QDicomServer(BaseServer):
    NAME = "dicom_server"
    DEFAULT_PORT = 11112

    def server_main(self):
        _q_s = self

        class CustomDUL(DULServiceProvider):
            def _send(self, pdu) -> None:
                # fix frequent attribute errors log spam during port scan
                with suppress(AttributeError):
                    super()._send(pdu)

            def _decode_pdu(self, bytestream: bytearray):
                pdu, event = super()._decode_pdu(bytestream)
                _q_s.log({"action": type(pdu).__name__, "data": {"data": str(pdu)}})
                return pdu, event

        class CustomAssociationServer(ae.AssociationServer):
            def process_request(
                self,
                request: socket | tuple[bytes, socket],
                client_address: tuple[str, int] | str,
            ):
                if isinstance(client_address, tuple):
                    src_ip, src_port = client_address
                else:
                    src_ip = client_address
                    src_port = None
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": src_ip,
                        "src_port": src_port,
                    }
                )
                super().process_request(request, client_address)

        def handle_event(event: evt.Event, *data):
            _q_s.log(
                {
                    "action": event.request.msg_type,
                    "data": {
                        "abstract_syntax": event.context.abstract_syntax,
                        "is_valid_request": event.request.is_valid_request,
                        "description": event.event.description,
                        "parameters": data,
                    },
                }
            )
            if isinstance(event, evt.EVT_DIMSE_RECV):
                return standard_dimse_recv_handler(event)
            if isinstance(event, evt.EVT_PDU_RECV):
                return standard_pdu_recv_handler(event)
            return SUCCESS

        handlers = [
            (event_, handle_event)
            for event_ in [*evt._INTERVENTION_EVENTS, *evt._NOTIFICATION_EVENTS]
        ]

        app_entity = ae.ApplicationEntity(ae_title="ORTHANC")

        storage_sop_classes = [cx.abstract_syntax for cx in AllStoragePresentationContexts]
        for uid in storage_sop_classes:
            app_entity.add_supported_context(uid, ALL_TRANSFER_SYNTAXES)
        app_entity.add_supported_context(Verification)

        for context in app_entity.supported_contexts:
            context.scp_role = True
            context.scu_role = False

        with (
            patch("pynetdicom.association.DULServiceProvider", CustomDUL),
            patch("pynetdicom.ae.AssociationServer", CustomAssociationServer),
        ):
            app_entity.start_server((self.ip, self.port), block=True, evt_handlers=handlers)


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        server = QDicomServer(
            ip=parsed.ip,
            port=parsed.port,
            options=parsed.options,
            config=parsed.config,
        )
        server.run_server()
