import json
import logging
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import sleep
from typing import Iterator

from paramiko.client import AutoAddPolicy, SSHClient

from honeypots import QSSHServer
from honeypots.__main__ import _parse_args, HoneypotsManager
from tests.utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

PORT = 50222
SERVER_CONFIG = {
    "honeypots": {
        "ssh": {
            "options": ["capture_commands"],
            "username": USERNAME,
            "password": PASSWORD,
        },
    },
    "logs": "file,terminal,json",
}


@contextmanager
def run_main(manager: HoneypotsManager):
    event = Event()
    thread = Thread(target=manager.main)
    manager.options.termination_strategy = event
    try:
        thread.start()
        yield
    finally:
        event.set()
        thread.join(timeout=5)
        assert not thread.is_alive()


@contextmanager
def config_for_testing(custom_config: dict) -> Iterator[Path]:
    with TemporaryDirectory() as tmp_dir:
        config = Path(tmp_dir) / "config.json"
        logs_output_dir = Path(tmp_dir) / "logs"
        logs_output_dir.mkdir()
        testing_config = {
            "logs": "file,terminal,json",
            "logs_location": str(logs_output_dir.absolute()),
            **custom_config,
        }
        config.write_text(json.dumps(testing_config))
        yield config


def test_full_run(caplog):
    with config_for_testing(SERVER_CONFIG) as config:
        sys.argv = [
            __file__,
            "--setup",
            "ssh",
            "--port",
            f"{PORT}",
            "--ip",
            IP,
            "--config",
            f"{config}",
        ]
        manager = HoneypotsManager(*_parse_args())

        with caplog.at_level(logging.INFO), run_main(manager), wait_for_server(PORT):
            sleep(0.1)  # make sure "connect" comes after "process"
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(IP, port=PORT, username=USERNAME, password=PASSWORD)
            ssh.close()

            assert len(manager.honeypots) == 1
            server, _, started = manager.honeypots[0]
            assert isinstance(server, QSSHServer)
            assert started is True
            assert server.ip == IP
            assert server.port == PORT
            assert server.username == USERNAME
            assert server.password == PASSWORD
            assert "capture_commands" in server.options

            logs = load_logs_from_file(config.parent / "logs")

        for string in [
            "Successfully loaded config file",
            '"action": "process"',
            "Everything looks good",
        ]:
            assert any(string in log for log in caplog.messages)

        assert len(logs) == 3
        logs_by_type = {e["action"]: e for e in logs}
        assert set(logs_by_type) == {"process", "login", "connection"}
        assert_connect_is_logged(logs_by_type["connection"], str(PORT))
        assert logs_by_type["login"]["username"] == USERNAME
