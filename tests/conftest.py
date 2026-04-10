import pytest
from script.deploy import deploy

@pytest.fixture
def qu_signer_contract():
    return deploy()
