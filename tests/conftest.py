import pytest
from src import QuSigner
from src.modules import XMSS
from moccasin.boa_tools import VyperContract

@pytest.fixture
def qu_signer_contract():
    return QuSigner.deploy()

@pytest.fixture
def xmss_contract():
    return XMSS.deploy()
