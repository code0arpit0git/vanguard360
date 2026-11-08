pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint) public balances;

    function isOwner(address owner) public view returns (bool) {
        return tx.origin == owner;
    }

    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        balances[msg.sender] = 0;
    }
}
