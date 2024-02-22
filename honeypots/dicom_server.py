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

from pynetdicom import AE, ALL_TRANSFER_SYNTAXES, AllStoragePresentationContexts, evt

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class DicomServer(BaseServer):
    NAME = "dicom_server"
    DEFAULT_PORT = 11112

    def server_main(self):
        _q_s = self

        def handle_store(event: evt.Event, _):
            """Handle EVT_C_STORE events."""
            _q_s.log(
                {
                    "action": "C-STORE",
                    "data": {
                        "meta": event.file_meta,
                    },
                }
            )

            return 0x0000

        handlers = [(evt.EVT_C_STORE, handle_store)]

        ae = AE()

        # FixMe?
        storage_sop_classes = [cx.abstract_syntax for cx in AllStoragePresentationContexts]
        for uid in storage_sop_classes:
            ae.add_supported_context(uid, ALL_TRANSFER_SYNTAXES)

        ae.start_server((self.ip, self.port), block=True, evt_handlers=handlers)


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        server = DicomServer(
            ip=parsed.ip,
            port=parsed.port,
            options=parsed.options,
            config=parsed.config,
        )
        server.run_server()
