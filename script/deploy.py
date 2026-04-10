from src import QuSigner
from moccasin.boa_tools import VyperContract

def deploy() -> VyperContract:
    qu_signer: VyperContract = QuSigner.deploy()
    return qu_signer

def moccasin_main() -> VyperContract:
    return deploy()
