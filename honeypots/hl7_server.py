"""
//  -------------------------------------------------------------
//  author        jstucke
//  project       qeeqbox/honeypots
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
"""
from __future__ import annotations

import re
from collections import defaultdict
from contextlib import suppress
from datetime import datetime, timezone
from random import randint

from hl7apy.core import Message, Field
from hl7apy.mllp import (
    AbstractErrorHandler,
    AbstractHandler,
    MLLPRequestHandler,
    MLLPServer,
    UnsupportedMessageType,
)
from hl7apy.parser import parse_message, parse_segment

from honeypots.base_server import BaseServer
from honeypots.helper import run_single_server

HL7_SPLIT_REGEX = re.compile(r"[_^]")


class Hl7Header:
    SENDING_APPLICATION = "MSH_3"
    SENDING_FACILITY = "MSH_4"
    RECEIVING_APPLICATION = "MSH_5"
    RECEIVING_FACILITY = "MSH_6"
    MESSAGE_TYPE = "MSH_9"
    MESSAGE_CONTROL_ID = "MSH_10"
    PROCESSING_ID = "MSH_11"
    VERSION_ID = "MSH_12"


class HL7Server(BaseServer):
    NAME = "hl7_server"
    DEFAULT_PORT = 2575

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomMLLPRequestHandler(MLLPRequestHandler):
            def _route_message(self, msg):
                src_ip, src_port = self.client_address
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": src_ip,
                        "src_port": src_port,
                    }
                )
                return super()._route_message(msg)

            def handle(self):
                with suppress(ConnectionResetError):
                    # we don't care about connection reset errors here
                    super().handle()

        class CustomPDQHandler(AbstractHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                try:
                    self.message = parse_message(self.incoming_message)
                    self.version = self._get_optional_field(Hl7Header.VERSION_ID) or "2.5"
                except Exception:
                    self.message = None
                    self.version = None
                self.response = Message("ACK", version=self.version) if self.version else None

            def reply(self):
                if not self.message:
                    return ""
                try:
                    _q_s.log(
                        {
                            "action": "query",
                            "data": {"message": self._parse_message()},
                        }
                    )
                    self._populate_header()
                    control_id = self._get_optional_field(Hl7Header.MESSAGE_CONTROL_ID)
                    # the "AA" means that the incoming message was accepted
                    ack_segment = parse_segment(f"MSA|AA|{control_id}", version=self.version)
                    self.response.add(ack_segment)
                except Exception as error:
                    _q_s.logger.debug(f"[{_q_s.NAME}] Error during response generation: {error}")
                return self.response.to_mllp()

            def _populate_header(self):
                # just swap sending/receiving app/facility and reuse the ID for the response
                self._add_field_to_header(
                    Hl7Header.SENDING_APPLICATION,
                    self._get_optional_field(Hl7Header.RECEIVING_APPLICATION),
                )
                self._add_field_to_header(
                    Hl7Header.SENDING_FACILITY,
                    self._get_optional_field(Hl7Header.RECEIVING_FACILITY),
                )
                self._add_field_to_header(
                    Hl7Header.RECEIVING_APPLICATION,
                    self._get_optional_field(Hl7Header.SENDING_APPLICATION),
                )
                self._add_field_to_header(
                    Hl7Header.RECEIVING_FACILITY,
                    self._get_optional_field(Hl7Header.SENDING_FACILITY),
                )
                self._add_field_to_header(
                    Hl7Header.MESSAGE_TYPE,
                    self._get_response_message_type(),
                )
                self._add_field_to_header(
                    Hl7Header.MESSAGE_CONTROL_ID,
                    str(randint(1000, 9000)),
                )
                self._add_field_to_header(
                    Hl7Header.PROCESSING_ID,
                    self._get_optional_field(Hl7Header.PROCESSING_ID),
                )
                # overwrite the date time field with one that includes milliseconds and a timezone
                t_str = datetime.now().astimezone(timezone.utc).strftime("%Y%m%d%H%M%S.%f%z")
                self.response.msh.msh_7.value = t_str[:-8] + t_str[-5:]  # µs -> ms

            def _get_response_message_type(self) -> str:
                try:
                    # the event code is part of the message type, and we need it for the response.
                    # structure is usually something like "ADT^A04[^ADT_A04]" [optional]
                    # with "A04" being the event code that we want
                    _, event, *_ = HL7_SPLIT_REGEX.split(
                        self._get_optional_field(Hl7Header.MESSAGE_TYPE)
                    )
                    return f"ACK^{event}"
                except (TypeError, ValueError):
                    # otherwise we just use "ACK" as message type
                    return "ACK"

            def _add_field_to_header(self, field: str, value: str):
                if value is None:
                    return
                message_type = Field(field, version=self.version)
                message_type.value = value
                self.response.msh.add(message_type)

            def _get_optional_field(self, field: str) -> str | None:
                try:
                    return getattr(self.message.msh, field).value
                except AttributeError:
                    return None

            def _parse_message(self):
                return [
                    {
                        "name": segment.name,
                        "raw": segment.to_er7(),
                        "fields": [
                            {
                                "name": field.name,
                                "type": field.long_name or field.datatype,
                                "value": field.value,
                            }
                            for field in segment.children
                        ],
                    }
                    for segment in self.message.children
                ]

        class ErrorHandler(AbstractErrorHandler):
            def reply(self):
                if isinstance(self.exc, UnsupportedMessageType):
                    _q_s.logger.error(f"Error: {self.exc}")
                    _q_s.log(
                        {
                            "action": "error",
                            "data": {"exception": str(self.exc)},
                        }
                    )

        # hack for the handler to receive all messages regardless of the message type
        handlers: dict[str, tuple] = defaultdict(lambda: (CustomPDQHandler,))
        handlers["ERR"] = (ErrorHandler,)
        server = MLLPServer(
            self.ip, self.port, handlers, request_handler_class=CustomMLLPRequestHandler
        )
        server.serve_forever()


if __name__ == "__main__":
    run_single_server(HL7Server)
