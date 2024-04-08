from __future__ import annotations

from pathlib import Path
from shlex import split
from subprocess import run
from time import sleep

import pytest
from pydicom import dcmread, Dataset
from pydicom.uid import CTImageStorage
from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind
from pynetdicom.pdu_primitives import UserIdentityNegotiation
from pynetdicom import AE, tests

from honeypots import QDicomServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
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
        proc = run(split(f"python -m pynetdicom echoscu {IP} {PORT}"), check=False)

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
        association = _retry_association(ae, PORT + 1, ext_neg=[user_identity])
        association.release()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 4
    connect, associate, login, release = logs
    assert_connect_is_logged(connect, PORT + 1)
    assert_login_is_logged(login)

    assert associate["action"] == "A-ASSOCIATE-RQ"
    assert release["action"] == "A-RELEASE-RQ"


def _retry_association(ae: AE, port: int, ext_neg=None):
    for _ in range(RETRIES):
        # this is somehow a bit flaky so we retry here
        association = ae.associate(IP, port, ext_neg=ext_neg)
        if association.is_established:
            return association
        sleep(1)
    pytest.fail("could not establish connection")


SERVER_CONFIG = {
    "honeypots": {
        "dicom": {
            "store_images": True,
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDicomServer, "port": PORT + 2, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_store(server_logs):
    dataset_path = Path(tests.__file__).parent / "dicom_files" / "CTImageStorage.dcm"
    dataset = dcmread(dataset_path)

    ae = AE()
    ae.add_requested_context(CTImageStorage)
    with wait_for_server(PORT + 2):
        association = _retry_association(ae, PORT + 2)
        response = association.send_c_store(dataset)
        association.release()

    assert isinstance(response, Dataset)
    assert response.Status == 0x0000  # success

    logs = load_logs_from_file(server_logs)
    assert len(logs) > 1
    logs_by_action = {entry["action"]: entry for entry in logs}
    assert "store_image" in logs_by_action
    assert logs_by_action["store_image"]["data"]["size"] == "39102"
