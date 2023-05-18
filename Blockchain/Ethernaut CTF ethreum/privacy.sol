// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Privacy {
    // chaque slote peut contenir 32 bytes = 256 bits
    // slot 0 car bool est égale à 32 bytes
  bool public locked = true;
  // slot 1 car uint256 est égale à 32 bytes
  uint256 public ID = block.timestamp;
    // slot 2 car uint8 est égale à 1 bytes
  uint8 private flattening = 10;
    // slot 2 car uint8 est égale à 1 bytes
  uint8 private denomination = 255;
    // slot 2 car uint8 est égale à 1 bytes
  uint16 private awkwardness = uint16(block.timestamp);
  // slot 3,4,5 car bytes32 est égale à 32 bytes
  bytes32[3] private data;

  constructor(bytes32[3] memory _data) {
    data = _data;
  }
    
    //on veut 16 bytes donc on prend les 16 premiers bytes de data[2] qui est un bytes32 donc 0x2415f2ba07c2ef20ba1d9fe528a85a49
  function unlock(bytes16 _key) public {
    require(_key == bytes16(data[2]));
    locked = false;
  }

  /*
    A bunch of super advanced solidity algorithms...

      ,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`
      .,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,
      *.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^         ,---/V\
      `*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.    ~|__(o.o)
      ^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'  UU  UU
  */
}
