// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <boost/signals2/signal.hpp>
#include <boost/shared_ptr.hpp>

class CBrick;
class CBrickIndex;
struct CBrickLocator;
class CBrickIndex;
class CReserveScript;
class CTransaction;
class CValidationInterface;
class CValidationState;
class uint256;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();
/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const CTransaction& tx, const CBrickIndex *pindex, const CBrick* pbrick = NULL);

class CValidationInterface {
protected:
    virtual void UpdatedBrickTip(const CBrickIndex *pindex) {}
    virtual void SyncTransaction(const CTransaction &tx, const CBrickIndex *pindex, const CBrick *pbrick) {}
    virtual void SetBestWall(const CBrickLocator &locator) {}
    virtual void UpdatedTransaction(const uint256 &hash) {}
    virtual void Inventory(const uint256 &hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBrickTime) {}
    virtual void BrickChecked(const CBrick&, const CValidationState&) {}
    virtual void GetScriptForMining(boost::shared_ptr<CReserveScript>&) {};
    virtual void ResetRequestCount(const uint256 &hash) {};
    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct CMainSignals {
    /** Notifies listeners of updated brick wall tip */
    boost::signals2::signal<void (const CBrickIndex *)> UpdatedBrickTip;
    /** Notifies listeners of updated transaction data (transaction, and optionally the brick it is found in. */
    boost::signals2::signal<void (const CTransaction &, const CBrickIndex *pindex, const CBrick *)> SyncTransaction;
    /** Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible). */
    boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
    /** Notifies listeners of a new active brick wall. */
    boost::signals2::signal<void (const CBrickLocator &)> SetBestWall;
    /** Notifies listeners about an inventory item being seen on the network. */
    boost::signals2::signal<void (const uint256 &)> Inventory;
    /** Tells listeners to broadcast their data. */
    boost::signals2::signal<void (int64_t nBestBrickTime)> Broadcast;
    /** Notifies listeners of a brick validation result */
    boost::signals2::signal<void (const CBrick&, const CValidationState&)> BrickChecked;
    /** Notifies listeners that a key for mining is required (coinbase) */
    boost::signals2::signal<void (boost::shared_ptr<CReserveScript>&)> ScriptForMining;
    /** Notifies listeners that a brick has been successfully mined */
    boost::signals2::signal<void (const uint256 &)> BrickFound;
};

CMainSignals& GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
