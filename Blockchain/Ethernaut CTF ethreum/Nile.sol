/*I wrote my first smart contract on Ethereum, deployed onto the Görli testnet, 
you have got to check it out! To celebrate it's launch, 
I'm giving away free tokens, you just have to redeem your balance. Connect to the server to see the contract address.

nc -v nile.chall.pwnoh.io 13379*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;


contract Nile {
    /* définie l'unique eth arddress a son type valeur */
    mapping(address => uint256) balance;
    mapping(address => uint256) redeemable;
    mapping(address => bool) accounts;


    //event exécuter par le contarct et qui seront inscrit dans la blockchain
    event GetFlag(bytes32);
    event Redeem(address, uint256);
    event Created(address, uint256);
    
    function redeem(uint amount) public {
        /* check si les condition account exist  and  sont vrai */
        require(accounts[msg.sender]);
        // require d'avoir plus de crypto a redeem que que de valeur demander 
        require(redeemable[msg.sender] > amount);


        /*https://ethereum.stackexchange.com/questions/42521/what-does-msg-sender-call-do-in-solidity*/
        /*https://www.alchemy.com/overviews/smart-contract-security-best-practices */
        /* quand on e */
        (bool status, ) = msg.sender.call(""); // ->  je dois chercher

        if (!status) {
            /* returning an invalid opcode error */ /* Voir EVM etherum c'est celui qui permet d'éxécuter les smart contract en bytecode*/
            revert();
        }

        // enleve la valeur redeem 
        redeemable[msg.sender] -= amount;

        //ajoute a la balance la crypto
        balance[msg.sender] += amount;

        emit Redeem(msg.sender, amount);
    }

    function createAccount() public {
        // crée un compte avec 100 de crypto a redeem
        balance[msg.sender] = 0;
        redeemable[msg.sender] = 100;
        accounts[msg.sender] = true;

        //log la transaction dans la blockchain
        emit Created(msg.sender, 100);
    }

    function createEmptyAccount() public {
        // empty account starts with 0 balance
        // donc pas de valeur a redeem
        balance[msg.sender] = 0;
        accounts[msg.sender] = true;
    }

    function deleteAccount() public {
        require(accounts[msg.sender]);
        balance[msg.sender] = 0;
        redeemable[msg.sender] = 0;
        accounts[msg.sender] = false;
    }

    function getFlag(bytes32 token) public {
        //Pour avoir le flag balance > 1000
        require(accounts[msg.sender]);
        require(balance[msg.sender] > 1000);

        emit GetFlag(token);
    }
}
