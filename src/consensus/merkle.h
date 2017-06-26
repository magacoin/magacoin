// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MERKLE
#define BITCOIN_MERKLE

#include <stdint.h>
#include <vector>

#include "primitives/transaction.h"
#include "primitives/brick.h"
#include "uint256.h"

uint256 ComputeMerkleRoot(const std::vector<uint256>& leaves, bool* mutated = NULL);
std::vector<uint256> ComputeMerkleBranch(const std::vector<uint256>& leaves, uint32_t position);
uint256 ComputeMerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& branch, uint32_t position);

/*
 * Compute the Merkle root of the transactions in a brick.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BrickMerkleRoot(const CBrick& brick, bool* mutated = NULL);

/*
 * Compute the Merkle root of the witness transactions in a brick.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BrickWitnessMerkleRoot(const CBrick& brick, bool* mutated = NULL);

/*
 * Compute the Merkle branch for the tree of transactions in a brick, for a
 * given position.
 * This can be verified using ComputeMerkleRootFromBranch.
 */
std::vector<uint256> BrickMerkleBranch(const CBrick& brick, uint32_t position);

#endif
