import sqlite3
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep

import pytest
from paramiko.client import AutoAddPolicy, SSHClient

from honeypots.__main__ import _parse_args, HoneypotsManager
from tests.utils import (
    IP,
    PASSWORD,
    USERNAME,
    wait_for_server,
    run_main,
    config_for_testing,
)

PORT = 50777
SERVER_CONFIG = {
    "honeypots": {
        "ssh": {
            "options": ["capture_commands"],
            "username": USERNAME,
            "password": PASSWORD,
        },
    },
    "logs": "db_sqlite",
    "sqlite_file": "/home/test.db",
    "db_options": ["drop"],
}


@pytest.fixture()
def db_path():
    with TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test.db"
        yield db_path


def _db_entry_to_dict(row: tuple) -> dict:
    _, _, server, action, _, _, _, dst_ip, dst_port, user, *_ = row
    return {
        "server": server,
        "action": action,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": user,
    }


def test_sqlite_logging(db_path):
    config = {**SERVER_CONFIG, "sqlite_file": str(db_path.absolute())}
    with config_for_testing(config) as config_path:
        sys.argv = [
            __file__,
            "--setup",
            "ssh",
            "--port",
            f"{PORT}",
            "--ip",
            IP,
            "--config",
            f"{config_path}",
        ]
        manager = HoneypotsManager(*_parse_args())

        with run_main(manager), wait_for_server(PORT):
            sleep(0.1)  # make sure "connect" comes after "process"
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(IP, port=PORT, username=USERNAME, password=PASSWORD)
            ssh.close()

            assert len(manager.honeypots) == 1

        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        result = [_db_entry_to_dict(row) for row in cursor.execute("SELECT * FROM servers_table")]
        assert len(result) == 3
        result_by_action = {entry["action"]: entry for entry in result}
        all(action in result_by_action for action in ("process", "connection", "login"))
        assert result_by_action["process"]["server"] == "ssh_server"
        assert result_by_action["connection"]["dst_ip"] == IP
        assert result_by_action["connection"]["dst_port"] == str(PORT)
        assert result_by_action["login"]["user"] == USERNAME
