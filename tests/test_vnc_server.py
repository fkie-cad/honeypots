from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path
from subprocess import run, TimeoutExpired
from time import sleep

import pytest

from honeypots import QVNCServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    USERNAME,
    PASSWORD,
    wait_for_server,
)

PW_FILE = Path(__file__).parent / "data" / "pw_file"
CONNECTOR = Path(__file__).parent / "data" / "vnc_connector.py"
PORT = "55900"


def _connect_to_vnc(port: str | None = None, password: str | None = None):
    # This VNC API creates a blocking daemon thread that can't be trivially stopped,
    # so we just run it in a subprocess and terminate that instead
    with suppress(TimeoutExpired):
        run(
            ["python3", str(CONNECTOR)],
            check=False,
            timeout=1,
            env={**os.environ, "IP": IP, "PORT": port, "USERNAME": USERNAME, "PASSWORD": password},
        )


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QVNCServer, "port": PORT}],
    indirect=True,
)
def test_vnc_server(server_logs):
    with wait_for_server(PORT):
        sleep(0.2)  # somehow the server isn't ready sometimes even though the port is occupied
        _connect_to_vnc(PORT, PASSWORD)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connection, login = logs
    assert_connect_is_logged(connection, PORT)
    assert login["action"] == "login"
    assert login["status"] == "success"
    assert login["username"] == ""
    assert login["password"] == PASSWORD


PORT2 = str(int(PORT) + 1)
SERVER_CONFIG = {
    "honeypots": {
        "vnc": {
            "file_name": str(PW_FILE),
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QVNCServer, "port": PORT2, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_wrong_pw(server_logs):
    with wait_for_server(PORT2):
        sleep(0.2)  # somehow the server isn't ready sometimes even though the port is occupied
        _connect_to_vnc(PORT2, "foo")

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connection, login = logs
    assert_connect_is_logged(connection, PORT2)
    assert login["action"] == "login"
    assert login["status"] == "failed"
    assert login["username"] == ""
    assert login["password"] == "foo"
