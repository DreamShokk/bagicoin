// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRIVATESENDCLIENT_H
#define BITCOIN_WALLET_PRIVATESENDCLIENT_H

#include <interfaces/chain.h>
#include <modules/masternode/masternode.h>
#include <modules/privatesend/privatesend.h>

struct CompactTallyItem;

class CPrivateSendClientManager;
class CReserveKey;
class CWallet;
class CConnman;

static const int DENOMS_COUNT_MAX                   = 100;

static const int MIN_PRIVATESEND_SESSIONS           = 1;
static const int MIN_PRIVATESEND_ROUNDS             = 2;
static const int MIN_PRIVATESEND_AMOUNT             = 2;
static const int MIN_PRIVATESEND_LIQUIDITY          = 0;
static const int MAX_PRIVATESEND_SESSIONS           = 10;
static const int MAX_PRIVATESEND_ROUNDS             = 16;
static const int MAX_PRIVATESEND_AMOUNT             = MAX_MONEY / COIN;
static const int MAX_PRIVATESEND_LIQUIDITY          = 100;
static const int DEFAULT_PRIVATESEND_SESSIONS       = 4;
static const int DEFAULT_PRIVATESEND_ROUNDS         = 2;
static const int DEFAULT_PRIVATESEND_AMOUNT         = 1000;
static const int DEFAULT_PRIVATESEND_LIQUIDITY      = 0;

static const bool DEFAULT_PRIVATESEND_MULTISESSION  = false;

// Warn user if mixing in gui or try to create backup if mixing in daemon mode
// when we have only this many keys left
static const int PRIVATESEND_KEYS_THRESHOLD_WARNING = 100;
// Stop mixing completely, it's too dangerous to continue when we have only this many keys left
static const int PRIVATESEND_KEYS_THRESHOLD_STOP    = 50;

class CKeyHolderStorage
{
private:
    std::vector<std::shared_ptr<CReserveKey> > storage;
    mutable CCriticalSection cs_storage;

public:
    void AddKey(std::shared_ptr<CReserveScript>& script, CWallet* pwalletIn);
    void KeepAll();
    void ReturnAll();

};

class CPendingDsaRequest
{
private:
    static const int TIMEOUT = 15;

    CService addr;
    CPrivateSendAccept dsa;
    int64_t nTimeCreated;

public:
    CPendingDsaRequest():
        addr(CService()),
        dsa(CPrivateSendAccept()),
        nTimeCreated(0)
    {
    }

    CPendingDsaRequest(const CService& addr_, const CPrivateSendAccept& dsa_):
        addr(addr_),
        dsa(dsa_),
        nTimeCreated(GetTime())
    {
    }

    CService GetAddr() { return addr; }
    CPrivateSendAccept GetDSA() { return dsa; }
    bool IsExpired() { return GetTime() - nTimeCreated > TIMEOUT; }

    friend bool operator==(const CPendingDsaRequest& a, const CPendingDsaRequest& b)
    {
        return a.addr == b.addr && a.dsa == b.dsa;
    }
    friend bool operator!=(const CPendingDsaRequest& a, const CPendingDsaRequest& b)
    {
        return !(a == b);
    }
    explicit operator bool() const
    {
        return *this != CPendingDsaRequest();
    }
};

/** Used to keep track of current status of mixing pool
 */
class CPrivateSendClientSession : public CPrivateSendBaseSession
{
private:
    CWallet* m_wallet_session;
    std::vector<COutPoint> vecOutPointLocked;

    int nEntriesCount;
    bool fLastEntryAccepted;

    std::string strLastMessage;
    std::string strAutoDenomResult;

    masternode_info_t infoMixingMasternode;
    CMutableTransaction txMyCollateral; // client side collateral
    CPendingDsaRequest pendingDsaRequest;

    CKeyHolderStorage keyHolderStorage; // storage for keys used in PrepareDenominate

    /// Create denominations
    bool CreateDenominated();
    bool CreateDenominated(const CompactTallyItem& tallyItem, bool fCreateMixingCollaterals);

    /// Split up large inputs or make fee sized inputs
    bool MakeCollateralAmounts();
    bool MakeCollateralAmounts(const CompactTallyItem& tallyItem, bool fTryDenominated);

    bool JoinExistingQueue(CAmount nBalanceNeedsAnonymized);
    bool StartNewQueue(CAmount nValueMin, CAmount nBalanceNeedsAnonymized);

    /// step 0: select denominated inputs and txouts
    bool SelectDenominate(std::string& strErrorRet, std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsRet);
    /// step 1: prepare denominated inputs and outputs
    bool PrepareDenominate(int nMinRounds, int nMaxRounds, std::string& strErrorRet, const std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsIn, std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsRet);
    /// step 2: send denominated inputs and outputs prepared in step 1
    bool SendDenominate(const std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsIn);

    /// Get Masternode updates about the progress of mixing
    bool CheckPoolStateUpdate(PoolState nStateNew, int nEntriesCountNew, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID, int nSessionIDNew = 0);
    // Set the 'state' value, with some logging and capturing when the state changed
    void SetState(PoolState nStateNew);

    /// Check for process
    void CheckPool();
    void CompletedTransaction(PoolMessage nMessageID);

    /// As a client, check and sign the final transaction
    bool SignFinalTransaction(const CTransaction& finalTransactionNew, CNode* pnode);

    void RelayIn(const CPrivateSendEntry& entry);

    void SetNull();

public:
    explicit CPrivateSendClientSession(CWallet* pwallet) :
        m_wallet_session(pwallet),
        vecOutPointLocked(),
        nEntriesCount(0),
        fLastEntryAccepted(false),
        strLastMessage(),
        strAutoDenomResult(),
        infoMixingMasternode(),
        txMyCollateral(),
        pendingDsaRequest(),
        keyHolderStorage()
    {
    }

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman);

    void UnlockCoins();

    void ResetPool();

    std::string GetStatus(bool fWaitForBlock);

    bool GetMixingMasternodeInfo(masternode_info_t& mnInfoRet) const;

    /// Passively run mixing in the background according to the configuration in settings
    void DoAutomaticDenominating();

    /// As a client, submit part of a future mixing transaction to a Masternode to start the process
    bool SubmitDenominate();

    bool ProcessPendingDsaRequest(CConnman *connman);

    bool CheckTimeout();
};

/** Used to keep track of current status of mixing pool
 */
class CPrivateSendClientManager : public CPrivateSendBaseManager
{
private:
    CWallet* m_wallet;
    // Keep track of the used Masternodes
    std::vector<COutPoint> vecMasternodesUsed;

    std::vector<CAmount> vecDenominationsSkipped;

    // TODO: or map<denom, CPrivateSendClientSession> ??
    std::deque<CPrivateSendClientSession> deqSessions;
    mutable CCriticalSection cs_deqsessions;

    int nCachedLastSuccessBlock;
    int nMinBlocksToWait; // how many blocks to wait after one successful mixing tx in non-multisession mode
    std::string strAutoDenomResult;

    // Keep track of current block height
    int nCachedBlockHeight;

    bool WaitForAnotherBlock();

    // Make sure we have enough keys since last backup
    bool CheckAutomaticBackup();

public:
    int nPrivateSendSessions;
    int nPrivateSendRounds;
    int nPrivateSendAmount;
    int nLiquidityProvider;
    bool fEnablePrivateSend;
    bool fPrivateSendMultiSession;

    int nCachedNumBlocks; //used for the overview screen
    bool fCreateAutoBackups; //builtin support for automatic backups

    explicit CPrivateSendClientManager(CWallet* pwallet) :
        m_wallet(pwallet),
        vecMasternodesUsed(),
        vecDenominationsSkipped(),
        deqSessions(),
        nCachedLastSuccessBlock(0),
        nMinBlocksToWait(1),
        strAutoDenomResult(),
        nCachedBlockHeight(0),
        nPrivateSendSessions(DEFAULT_PRIVATESEND_SESSIONS),
        nPrivateSendRounds(DEFAULT_PRIVATESEND_ROUNDS),
        nPrivateSendAmount(DEFAULT_PRIVATESEND_AMOUNT),
        nLiquidityProvider(DEFAULT_PRIVATESEND_LIQUIDITY),
        fEnablePrivateSend(false),
        fPrivateSendMultiSession(DEFAULT_PRIVATESEND_MULTISESSION),
        nCachedNumBlocks(std::numeric_limits<int>::max()),
        fCreateAutoBackups(true)
    {
    }

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman);

    bool IsDenomSkipped(const CAmount& nDenomValue);
    void AddSkippedDenom(const CAmount& nDenomValue);
    void ClearSkippedDenominations() { vecDenominationsSkipped.clear(); }

    void SetMinBlocksToWait(int nMinBlocksToWaitIn) { nMinBlocksToWait = nMinBlocksToWaitIn; }

    void ResetPool();

    std::string GetStatuses();
    std::string GetSessionDenoms();

    bool GetMixingMasternodesInfo(std::vector<masternode_info_t>& vecMnInfoRet) const;

    bool IsMixingMasternode(const CNode* pnode) const;

    /// Passively run mixing in the background according to the configuration in settings
    void DoAutomaticDenominating();

    void CheckTimeout();

    void ProcessPendingDsaRequest();

    void AddUsedMasternode(const COutPoint& outpointMn);
    masternode_info_t GetNotUsedMasternode();

    void UpdatedSuccessBlock();

    void UpdatedBlockTip(const int nHeight);
    void ClientTask();
};

#endif
