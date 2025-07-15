+++
title = "Transient Heist Revenge"
date = 2025-07-15
authors = ["Vrishab"]
+++

## Overview

The main goal of the challenge is to trick the function `isSolved` from Setup.sol into completing. There are 2 main entities here:

- **Bank Vault** (USDSEngine): This is a very secure vault that stores collateral and allows minting of USDS stablecoin. It uses transient storage (tstore/tload) to verify only the correct Bi0sSwapPair can call certain functions.
- **Currency Exchange** (Bi0sSwapPair): This booth swaps one type of token for another.

We need to trick the Vault into thinking we’ve deposited a huge amount as collateral - it has to be more than a very large hash value.

## How Collateral Deposits Work

Collateral Deposits normally work like this:

1. A user calls `depositCollateralThroughSwap` to deposit collateral via an automated token swap.
2. The vault transfers tokens to the Bi0sSwapPair, writes the swap pair’s address into transient storage (`tstore(1, bi0sSwapPair)`).
3. The swap is performed, and upon completion, the Bi0sSwapPair calls back into `bi0sSwapv1Call` to deposit the collateral.
4. In `bi0sSwapv1Call`, the vault checks that `msg.sender` matches the stored address from transient storage, ensures the requested collateral deposit is not greater than the amount of tokens received (`collateralDepositAmount <= amountOut`), and updates internal collateral balances.

## The Vulnerability

Now, the only check on who can call `bi0sSwapv1Call` is the transient storage slot. This means that if an attacker can use the value written into transient storage, they can then call `bi0sSwapv1Call` from their own contract address. The vault only checks `msg.sender == tload(1)`, but `tload(1)` gets overwritten during the callback with `tokensSentToUserVault`, allowing us to control this value.

## Exploit Steps

**1. Deploying a malicious contract at a controlled address** - we use CREATE2 to deploy an attacker contract at an address that can be precomputed. This contract must implement the `bi0sSwapv1Call` function. A contract is used instead of a normal wallet since only contracts can call `bi0sSwapv1Call` and pass the transient storage check while being deployed at a known address. We should ensure we get a contract address with sufficient leading zeros for the arithmetic manipulation.

**2. Initiating a Legitimate Swap** - we now call `depositCollateralThroughSwap` with 80,000 WETH which we want to swap for SafeMoon. This triggers `tstore(1, bi0sSwapPair)` - usage of transient storage which survives for the entire transaction, not just the swap call.

**3. Overwrite Transient Storage During First Callback**: During the legitimate `bi0sSwapv1Call` callback, we set `collateralDepositAmount = amountOut - vanity_contract_address`, making `tokensSentToUserVault = vanity_contract_address`. The line `tstore(1, tokensSentToUserVault)` then overwrites the original swap pair address with our contract address.

**4. Second Call to bi0sSwapv1Call**: Within the same transaction, we call `bi0sSwapv1Call` directly from our vanity contract. The check `msg.sender == tload(1)` now passes because `tload(1)` contains our contract address from step 3.

**5. Set Arbitrary Collateral Amounts**: In the second call, we can supply ANY `amountOut` and `collateralDepositAmount > FLAG_HASH` (ensuring `collateralDepositAmount <= amountOut`). These don't need to be realistic token amounts - just arbitrary large numbers.

**6. Repeat for Second Token**: The `isSolved()` function requires BOTH `collateralTokens[0]` (WETH) AND `collateralTokens[1]` (SafeMoon) to exceed `FLAG_HASH`. Since transient storage persists for the entire transaction, you can make a second direct call to `bi0sSwapv1Call` with the other token type using the same poisoned transient storage.

## Arithmetic Manipulation Used

The exploit requires careful calculation: `tokensSentToUserVault = amountOut - collateralDepositAmount` must equal the vanity contract address. We need a vanity address with 7+ leading zeros to make this arithmetic feasible compared to `FLAG_HASH`.

## Why the Vanity Address Matters

- We need a contract deployed at a **small numeric address** (7 leading zeros) to make the arithmetic work.
- The calculation `tokensSentToUserVault = amountOut - collateralDepositAmount` must equal our contract address.
- We need an address comparatively smaller than `FLAG_HASH` so that in the first callback, `amountOut = vanityAddress + smallCollateralAmount` is achievable through legitimate token swaps, while in the second call you can use `collateralDepositAmount > FLAG_HASH`.
- This address then gets written to transient storage, allowing our contract to **pass the `msg.sender` check** on the second call.

