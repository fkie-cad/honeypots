from __future__ import annotations

from shlex import split
from subprocess import run
from time import sleep

import pytest
from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind
from pynetdicom.pdu_primitives import UserIdentityNegotiation
from pynetdicom import AE

from honeypots import QDicomServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

USER_AND_PW = 2
RETRIES = 3
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

    assert len(logs) == 5
    connect, *events = logs
    assert_connect_is_logged(connect, PORT)

    assert events[0]["action"] == "A-ASSOCIATE-RQ"
    assert events[1]["action"] == "P-DATA-TF"
    assert events[2]["action"] == "C-ECHO"
    assert events[3]["action"] == "A-RELEASE-RQ"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDicomServer, "port": PORT + 1}],
    indirect=True,
)
def test_login(server_logs):
    ae = AE()
    ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)

    user_identity = UserIdentityNegotiation()
    user_identity.user_identity_type = USER_AND_PW
    user_identity.primary_field = USERNAME.encode()
    user_identity.secondary_field = PASSWORD.encode()

    with wait_for_server(PORT + 1):
        for _ in range(RETRIES):
            # this is somehow a bit flaky so we retry here
            assoc = ae.associate("127.0.0.1", PORT + 1, ext_neg=[user_identity])
            if assoc.is_established:
                assoc.release()
                break
            sleep(1)
        else:
            pytest.fail("could not establish connection")

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 4
    connect, associate, login, release = logs
    assert_connect_is_logged(connect, PORT + 1)
    assert_login_is_logged(login)

    assert associate["action"] == "A-ASSOCIATE-RQ"
    assert release["action"] == "A-RELEASE-RQ"
