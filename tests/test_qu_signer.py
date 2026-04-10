def test_increment(qu_signer_contract):
    number: int = qu_signer_contract.number()
    qu_signer_contract.increment()
    assert qu_signer_contract.number() == number + 1
