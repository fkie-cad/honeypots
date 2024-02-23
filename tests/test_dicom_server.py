from __future__ import annotations

from shlex import split
from subprocess import run

import pytest
from pydicom import Dataset
from pynetdicom import AE

from honeypots import QDicomServer
from .utils import (
    assert_connect_is_logged,
    load_logs_from_file,
    wait_for_server,
)

PORT = 61112


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDicomServer, "port": PORT}],
    indirect=True,
)
def test_dicom_echo(server_logs):
    with wait_for_server(PORT):
        proc = run(split(f"python -m pynetdicom echoscu 127.0.0.1 {PORT}"), check=False)

    assert proc.returncode == 0

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, action = logs
    assert_connect_is_logged(connect, PORT)

    assert action["action"] == "C-ECHO"
    assert action["data"]["is_valid_request"] == "True"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDicomServer, "port": PORT + 1}],
    indirect=True,
)
def test_associate(server_logs):
    ds = Dataset()
    ds.PatientName = "CITIZEN^Jan"
    ds.QueryRetrieveLevel = "PATIENT"
    ds.SOPClassUID = "1.2.840.10008.5"
    ds.SOPInstanceUID = "1.2.840.10008"
    ds.compress(transfer_syntax_uid="1.2.840.10008.1.2.5")

    with wait_for_server(PORT + 1):
        ae = AE()
        ae.add_requested_context("1.2.840.10008.1.1")
        assoc = ae.associate("127.0.0.1", PORT + 1)
        assert assoc.is_established
        status = assoc.send_c_store(ds)
        assert status is None
        assoc.release()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
