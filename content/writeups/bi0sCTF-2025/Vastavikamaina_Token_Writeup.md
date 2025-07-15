+++
title = "Vasthavikamaina Token Exploit"
date = 2025-07-15
authors = ["Vrishab"]
+++


## Overview

This exploit leverages a critical vulnerability in the `addVasthavikamainaLiquidity` function to manipulate AMM pool economics and extract profit without bearing the debt burden. The system creates three different machines (pools), but one of them, named "CowrieBO" (uniPair2), is set up with very little starting money; only 0.05 ETH. This makes it very easy to manipulate.

## The Vulnerability

The `addVasthavikamainaLiquidity` function contains a fatal flaw:

- It sends loans directly to Uniswap pairs - which are the AMM pools
- The `msg.sender` only provides matching tokens proportionally
- LP tokens are burned to `address(0)`, making the liquidity permanent
- **Result**: Massive liquidity gets added at manipulated prices with zero debt for us

## Attack Steps

### 1. Initial Setup

- Flash loan WETH from Balancer contract for capital, which must be repaid in the same transaction
- Convert WETH to VSTETH via `cashIn()`

### 2. Price Manipulation

- Execute `buyQuote()` on target pool (preferably Pool 2 - CowrieBO)
- This drains pool reserves and inflates lamboToken price
- Small initial buy (0.05 ETH) means maximum price impact

### 3. Liquidity Amplification (Core Exploit)

```solidity
factory.addVasthavikamainaLiquidity(VSTETH, lamboToken, 300 ether, 0);
```

- Function calculates: `lamboTokensNeeded = (300 ETH * reserve1) / reserve0`
- **300 ETH loan goes directly to the machine** (not to us)
- We only transfer the calculated lamboTokens (which is very less due to the flaw)
- Pool's K-value jumps from small amount to massive: `K = (reserve0 + 300e18) × (reserve1 + proportional_tokens)`

### 4. Profit Extraction

- Sell remaining lamboTokens back to the enhanced pool
- The amplified liquidity provides much better exchange rates
- Pool now has deep liquidity at the inflated price we set

## Why This Works

1. **Debt Isolation**: The 300 ETH debt belongs to the Uniswap pair, not us
2. **K-Value Manipulation**: Adding massive liquidity at inflated prices creates favorable AMM constants
3. **Permanent Enhancement**: Burned LP tokens mean the enhanced liquidity can't be withdrawn
4. **Arbitrage Profit**: Selling back tokens yields more ETH than originally invested due to the deeper, manipulated pool

## Economic Impact

- Input: ~6.35 ETH (flash loan + small buys)
- Output: >141.3 ETH profit
- The exploit tricks the AMM into providing permanent liquidity at prices controlled by us

## Target Pool

**Pool 2 (CowrieBO)** is optimal because:

- Minimal initial buy (0.05 ETH)
- Lowest starting lamboToken price
- Thereby maximum manipulation potential per ETH spent

