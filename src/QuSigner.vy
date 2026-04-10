# pragma version ^0.4.1
# @license MIT

number: public(uint256)

@external
def set_number(_new_number: uint256):
    self.number = _new_number

@external
def increment():
    self.number += 1
