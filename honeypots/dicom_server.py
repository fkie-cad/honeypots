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
from enum import Enum
from typing import TYPE_CHECKING
from unittest.mock import patch

from pynetdicom import (
    ae,
    ALL_TRANSFER_SYNTAXES,
    AllStoragePresentationContexts,
    evt,
    RelevantPatientInformationPresentationContexts,
    VerificationPresentationContexts,
    QueryRetrievePresentationContexts,
)
from pynetdicom.dul import DULServiceProvider

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)

if TYPE_CHECKING:
    from socket import socket

UNINTERESTING_EVENTS = {
    "EVT_ASYNC_OPS",
    "EVT_SOP_EXTENDED",
    "EVT_SOP_COMMON",
}


class UserIdType(Enum):
    username = 1
    username_and_passcode = 2
    kerberos = 3
    saml = 4
    jwt = 5


SUCCESS = 0x0000


class QDicomServer(BaseServer):
    NAME = "dicom_server"
    DEFAULT_PORT = 11112

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomDUL(DULServiceProvider):
            def _send(self, pdu) -> None:
                # fix frequent attribute error log spam during port scan
                with suppress(AttributeError):
                    super()._send(pdu)

            def _decode_pdu(self, bytestream: bytearray):
                pdu, event = super()._decode_pdu(bytestream)
                try:
                    _q_s.log(
                        {
                            "action": type(pdu).__name__.replace("_", "-"),
                            "data": _dicom_obj_to_dict(pdu),
                        }
                    )
                except Exception as error:
                    _q_s.logger.debug(f"Error while decoding PDU: {error}")
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

        def handle_login(event: evt.Event, *_) -> tuple[bool, bytes | None]:
            # EVT_USER_ID event
            # see https://pydicom.github.io/pynetdicom/stable/reference/generated/pynetdicom._handlers.doc_handle_userid.html
            user_id_type = UserIdType(event.user_id_type)
            if user_id_type == UserIdType.username_and_passcode:
                username = event.primary_field.decode()
                password = event.secondary_field.decode()
                success = _q_s.check_login(
                    username,
                    password,
                    ip=event.assoc.requestor.address,
                    port=event.assoc.requestor.port,
                )
                return success, None
            if user_id_type == UserIdType.username:
                username = event.primary_field.decode()
                _q_s.log(
                    {
                        "action": "login",
                        "username": username,
                        "status": "success",
                        "data": {"login_format": user_id_type.name},
                    }
                )
                return True, None
            if user_id_type == UserIdType.kerberos:
                _log_id_event("kerberos_ticket", event)
            elif user_id_type == UserIdType.jwt:
                _log_id_event("json_web_token", event)
            else:  # SAML
                _log_id_event("saml_assertion", event)
            return False, None

        def _log_id_event(data_type: str, event: evt.Event):
            _q_s.log(
                {
                    "action": "login",
                    "status": "failed",
                    "data": {
                        "login_format": UserIdType(event.user_id_type).name,
                        data_type: event.primary_field.decode(),
                    },
                }
            )

        def handle_event(event: evt.Event, *_):
            # generic event handler
            try:
                data = {
                    "description": event.event.description,
                }
                if hasattr(event, "context"):
                    data.update(
                        {
                            "abstract_syntax": event.context.abstract_syntax,
                            "transfer_syntax": event.context.transfer_syntax,
                        }
                    )
                _q_s.log(
                    {
                        "action": event.event.name.replace("EVT_", "").replace("_", "-"),
                        "src_ip": event.assoc.requestor.address,
                        "src_port": event.assoc.requestor.port,
                        "data": data,
                    }
                )
            except Exception as error:
                _q_s.logger.critical(f"exception during event logging: {error}")
            return SUCCESS

        handlers = [
            (event_, handle_event) if event_.name != "EVT_USER_ID" else (event_, handle_login)
            for event_ in evt._INTERVENTION_EVENTS
            if event_.name not in UNINTERESTING_EVENTS
        ]

        app_entity = ae.ApplicationEntity(ae_title="PACS")

        for context_list in (
            # these are the contexts our server supports
            AllStoragePresentationContexts,
            RelevantPatientInformationPresentationContexts,
            QueryRetrievePresentationContexts,
            VerificationPresentationContexts,
        ):
            for context in context_list:
                app_entity.add_supported_context(context.abstract_syntax, ALL_TRANSFER_SYNTAXES)

        for context in app_entity.supported_contexts:
            # only play the server role, not the client
            context.scp_role = True
            context.scu_role = False

        with patch("pynetdicom.association.DULServiceProvider", CustomDUL), patch(
            "pynetdicom.ae.AssociationServer", CustomAssociationServer
        ):
            app_entity.start_server((self.ip, self.port), block=True, evt_handlers=handlers)


def _dicom_obj_to_dict(pdu) -> dict[str, str | list[dict[str, str]]]:
    # pynetdicom classes implement custom formatted print methods which we can use
    result = {}
    for line in str(pdu).splitlines():
        try:
            key, value = line.split(":")
            if not key or not value:
                continue
            result.update({key.strip("\t -"): value.strip("'= ")})
        except ValueError:
            continue
    if hasattr(pdu, "application_context_name"):
        result["application_context"] = pdu.application_context_name
    if hasattr(pdu, "presentation_data_value_items"):
        result["presentation_context"] = [
            _dicom_obj_to_dict(item) for item in pdu.presentation_data_value_items
        ]
    if hasattr(pdu, "presentation_context"):
        result["presentation_context"] = [
            _dicom_obj_to_dict(_context) for _context in pdu.presentation_context
        ]
    if hasattr(pdu, "user_information") and hasattr(pdu.user_information, "user_data"):
        result["user_information"] = [
            _dicom_obj_to_dict(item) for item in pdu.user_information.user_data
        ]
    return result


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
