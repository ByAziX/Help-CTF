// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
  bool public locked;
  bytes32 private password;

  constructor(bytes32 _password) {
    locked = true;
    password = _password;
  }

  function unlock(bytes32 _password) public {
    if (password == _password) {
      locked = false;
    }
  }
}


// go to https://mumbai.polygonscan.com/tx/0x6927896894a6684591660004f362498510bc5595c32f1762cea3ca66fb151f69#eventlog