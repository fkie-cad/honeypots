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
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

from pydicom import dcmread
from pydicom.filewriter import write_file_meta_info
from pynetdicom import (
    ae,
    ALL_TRANSFER_SYNTAXES,
    AllStoragePresentationContexts,
    evt,
    RelevantPatientInformationPresentationContexts,
    VerificationPresentationContexts,
    QueryRetrievePresentationContexts,
    tests,
)
from pynetdicom.dul import DULServiceProvider

from honeypots.base_server import BaseServer
from honeypots.helper import (
    run_single_server,
)

if TYPE_CHECKING:
    from socket import socket

UNINTERESTING_EVENTS = {
    "EVT_ASYNC_OPS",
    "EVT_SOP_EXTENDED",
    "EVT_SOP_COMMON",
}
GET_REQUEST_DS = dcmread(Path(tests.__file__).parent / "dicom_files" / "CTImageStorage.dcm")


class UserIdType(Enum):
    username = 1
    username_and_passcode = 2
    kerberos = 3
    saml = 4
    jwt = 5


SUCCESS = 0x0000
FAILURE = 0xC000
CANCEL = 0xFE00
PENDING = 0xFF00


class QDicomServer(BaseServer):
    NAME = "dicom_server"
    DEFAULT_PORT = 11112

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.store_images = bool(getattr(self, "store_images", False))
        if hasattr(self, "storage_dir") and isinstance(self.storage_dir, str):
            self.storage_dir = Path(self.storage_dir)
        else:
            self.storage_dir = Path("/tmp/dicom_storage")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def server_main(self):  # noqa: C901,PLR0915
        _q_s = self

        class CustomDUL(DULServiceProvider):
            def _send(self, pdu) -> None:
                # fix frequent attribute error log spam during port scan
                with suppress(AttributeError):
                    super()._send(pdu)

            def _decode_pdu(self, bytestream: bytearray):
                pdu, event = super()._decode_pdu(bytestream)
                try:
                    pdu_type = type(pdu).__name__.replace("_", "-")
                    if pdu_type != "P-DATA-TF":
                        _q_s.log(
                            {
                                "action": pdu_type,
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

        def handle_store(event: evt.Event) -> int:
            _log_event(event)
            try:
                output_file = _q_s.storage_dir / event.request.AffectedSOPInstanceUID
                with output_file.open("wb") as fp:
                    preamble = b"\x00" * 128
                    prefix = b"DICM"
                    fp.write(preamble + prefix)
                    write_file_meta_info(fp, event.file_meta)
                    fp.write(event.request.DataSet.getvalue())
                _q_s.log(
                    {
                        "action": "store_image",
                        "data": {"path": str(output_file), "size": output_file.stat().st_size},
                    }
                )
                return SUCCESS
            except Exception as error:
                _q_s.logger.critical(f"Exception occurred during store event: {error}")
                return FAILURE

        def handle_get(event):
            # C-GET event
            # see docs: https://pydicom.github.io/pynetdicom/stable/reference/generated/pynetdicom._handlers.doc_handle_c_get.html#pynetdicom._handlers.doc_handle_c_get
            _log_get_move_event(event)

            if not event.identifier or "QueryRetrieveLevel" not in event.identifier:
                # if this is a valid GET request, there should be a retrieve level
                yield FAILURE, None
                return

            # we simply always return the same demo dataset instead of
            # checking if anything actually matched the IDs in the request
            instances = [GET_REQUEST_DS]

            # first yield the number of operations
            yield len(instances)

            # then yield the "matching" instance
            for instance in instances:
                if event.is_cancelled:
                    yield CANCEL, None
                    return
                yield PENDING, instance

        def handle_move(event):
            # C-MOVE request event
            _log_get_move_event(event)

            if not event.identifier or "QueryRetrieveLevel" not in event.identifier:
                yield FAILURE, None
                return

            # we can't actually know the requested destination server (and even if it is the
            # same one that send the request we don't know the port), so we yield (None, None)
            # which results in the server returning 0xA801 (move destination unknown)
            yield None, None

        def _log_get_move_event(event):
            dataset = event.identifier
            log_data = {
                key: getattr(dataset, key, None)
                for key in (
                    "QueryRetrieveLevel",
                    "PatientID",
                    "StudyInstanceUID",
                    "SeriesInstanceUID",
                )
            }
            _log_event(event, log_data)

        def handle_login(event: evt.Event) -> tuple[bool, bytes | None]:
            # USER-ID event
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
            _log_event(event)
            return SUCCESS

        def _log_event(event, additional_data: dict | None = None):
            additional_data = additional_data or {}
            try:
                if hasattr(event, "context"):
                    additional_data.update(
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
                        "data": {
                            "description": event.event.description,
                            **additional_data,
                        },
                    }
                )
            except Exception as error:
                _q_s.logger.debug(f"exception during event logging: {error}")

        special_handlers = {
            evt.EVT_USER_ID.name: handle_login,
            evt.EVT_C_GET.name: handle_get,
            evt.EVT_C_MOVE.name: handle_move,
        }
        if _q_s.store_images:
            special_handlers[evt.EVT_C_STORE.name] = handle_store
        handlers = [
            (event_, special_handlers.get(event_.name, handle_event))
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
            if context in AllStoragePresentationContexts:
                # except when presenting things (get request) then the server is also the SCU
                context.scp_role = True
                context.scu_role = True
            else:
                context.scp_role = True
                context.scu_role = False

        with patch("pynetdicom.association.DULServiceProvider", CustomDUL), patch(
            "pynetdicom.ae.AssociationServer", CustomAssociationServer
        ):
            app_entity.start_server(
                (self.ip, self.port),
                block=True,
                evt_handlers=handlers,
            )


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
    run_single_server(QDicomServer)
