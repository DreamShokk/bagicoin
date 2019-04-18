// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MODULES_COINJOIN_COINJOIN_H
#define BITCOIN_MODULES_COINJOIN_COINJOIN_H

#include <chain.h>
#include <chainparams.h>
#include <primitives/transaction.h>
#include <psct.h>
#include <pubkey.h>
#include <sync.h>
#include <timedata.h>
#include <tinyformat.h>

class CCoinJoin;
class CConnman;

// denominations
static const unsigned char COINJOIN_MAX_SHIFT = 0x0b;
static const CAmount COINJOIN_BASE_DENOM = 102400000;
// boundaries for convenience
static const CAmount COINJOIN_HIGH_DENOM = COINJOIN_BASE_DENOM << COINJOIN_MAX_SHIFT;
static const CAmount COINJOIN_LOW_DENOM = COINJOIN_BASE_DENOM >> COINJOIN_MAX_SHIFT;

// timeout used by the session
static const int COINJOIN_QUEUE_TIMEOUT          = 600;
// time for all participants to sign
static const int COINJOIN_SIGNING_TIMEOUT        = 30;
// timeout for queues in blocks
static const int COINJOIN_DEFAULT_TIMEOUT        = 10;

//! minimum peer version accepted by mixing pool
static const int MIN_COINJOIN_PEER_PROTO_VERSION            = 70017;
//! maximum number of inputs on a single pool transaction
static const size_t COINJOIN_ENTRY_MAX_SIZE                 = 98;
//! number of denoms each size before new ones are created
static const unsigned int COINJOIN_DENOM_THRESHOLD          = 3;
//! number of denoms each size before new ones are created
static const unsigned int COINJOIN_FEE_DENOM_THRESHOLD      = 9;
//! number of denoms each size before new ones are created
static const unsigned int COINJOIN_DENOM_WINDOW             = 3;

// pool responses
enum PoolMessage {
    ERR_ALREADY_HAVE,
    ERR_DENOM,
    ERR_ENTRIES_FULL,
    ERR_INVALID_OUT,
    ERR_FEES,
    ERR_INVALID_INPUT,
    ERR_INVALID_SCRIPT,
    ERR_INVALID_TX,
    ERR_MAXIMUM,
    ERR_MN_LIST,
    ERR_MODE,
    ERR_NON_STANDARD_PUBKEY,
    ERR_NOT_A_MN, // not used
    ERR_QUEUE_FULL,
    ERR_RECENT,
    ERR_SESSION,
    ERR_MISSING_TX,
    ERR_VERSION,
    MSG_NOERR,
    MSG_SUCCESS,
    MSG_ENTRIES_ADDED,
    MSG_POOL_MIN = ERR_ALREADY_HAVE,
    MSG_POOL_MAX = MSG_ENTRIES_ADDED
};

// pool states
enum PoolState {
    POOL_STATE_IDLE,
    POOL_STATE_CONNECTING,
    POOL_STATE_QUEUE,
    POOL_STATE_ACCEPTING_ENTRIES,
    POOL_STATE_SIGNING,
    POOL_STATE_ERROR,
    POOL_STATE_SUCCESS,
    POOL_STATE_MIN = POOL_STATE_IDLE,
    POOL_STATE_MAX = POOL_STATE_SUCCESS
};

// status update message constants
enum PoolStatusUpdate {
    STATUS_REJECTED,
    STATUS_ACCEPTED
};

// A clients transaction in the mixing pool
class CCoinJoinEntry
{
public:
    int nSessionID;
    PartiallySignedTransaction psctx;
    // mem only
    CService addr;

    CCoinJoinEntry() :
        nSessionID(0),
        psctx(PartiallySignedTransaction()),
        addr(CService())
    {
    }

    CCoinJoinEntry(const int& nSessionID, const PartiallySignedTransaction& psctx) :
        nSessionID(nSessionID),
        psctx(psctx),
        addr(CService())
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nSessionID);
        READWRITE(psctx);
    }
};


/**
 * A currently in progress mixing merge and denomination information
 */
class CCoinJoinQueue
{
public:
    CAmount nDenom;
    COutPoint masternodeOutpoint;
    int nHeight;
    bool fReady; //ready for submit
    bool fOpen;
    std::vector<unsigned char> vchSig;
    // memory only
    bool fTried;

    CCoinJoinQueue() :
        nDenom(0),
        masternodeOutpoint(COutPoint()),
        nHeight(0),
        fReady(false),
        fOpen(true),
        vchSig(std::vector<unsigned char>()),
        fTried(false)
    {
    }

    CCoinJoinQueue(CAmount _nDenom, COutPoint _outpoint, int _nHeight, bool _fReady, bool _fOpen) :
        nDenom(_nDenom),
        masternodeOutpoint(_outpoint),
        nHeight(_nHeight),
        fReady(_fReady),
        fOpen(_fOpen),
        vchSig(std::vector<unsigned char>()),
        fTried(false)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nDenom);
        READWRITE(masternodeOutpoint);
        READWRITE(nHeight);
        READWRITE(fReady);
        READWRITE(fOpen);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
    }

    uint256 GetSignatureHash() const;
    /** Sign this mixing transaction
     *  \return true if all conditions are met:
     *     1) we have an active Masternode,
     *     2) we have a valid Masternode private key,
     *     3) we signed the message successfully, and
     *     4) we verified the message successfully
     */
    bool Sign();
    /// Check if we have a valid Masternode address
    bool CheckSignature(const CPubKey& pubKeyMasternode) const;

    bool Relay(CConnman* connman);

    /// Is this queue expired?
    bool IsExpired(int nHeightIn) { return nHeightIn - nHeight > COINJOIN_DEFAULT_TIMEOUT; }

    std::string ToString() const
    {
        return strprintf("nDenom=%d, nHeight=%lld, fReady=%s, fOpen=%s, fTried=%s, masternode=%s",
            nDenom, nHeight, fReady ? "true" : "false", fOpen ? "true" : "false", fTried ? "true" : "false", masternodeOutpoint.ToStringShort());
    }

    friend bool operator==(const CCoinJoinQueue& a, const CCoinJoinQueue& b)
    {
        return a.nDenom == b.nDenom && a.masternodeOutpoint == b.masternodeOutpoint && a.nHeight == b.nHeight && a.fReady == b.fReady;
    }
};

/** Helper class to store mixing transaction (tx) information.
 */
class CCoinJoinBroadcastTx
{

public:
    int nSessionID;
    PartiallySignedTransaction psctx;
    COutPoint masternodeOutpoint;
    std::vector<unsigned char> vchSig;
    int64_t sigTime;

    CCoinJoinBroadcastTx() :
        nSessionID(0),
        psctx(),
        masternodeOutpoint(),
        vchSig(),
        sigTime(0)
    {
    }

    CCoinJoinBroadcastTx(const int& _nSessionID, const PartiallySignedTransaction& _psctx, COutPoint _outpoint, int64_t _sigTime) :
        nSessionID(_nSessionID),
        psctx(_psctx),
        masternodeOutpoint(_outpoint),
        vchSig(),
        sigTime(_sigTime)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nSessionID);
        READWRITE(psctx);
        READWRITE(masternodeOutpoint);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(vchSig);
        }
        READWRITE(sigTime);
    }

    friend bool operator==(const CCoinJoinBroadcastTx& a, const CCoinJoinBroadcastTx& b)
    {
        return *a.psctx.tx == *b.psctx.tx;
    }
    friend bool operator!=(const CCoinJoinBroadcastTx& a, const CCoinJoinBroadcastTx& b)
    {
        return !(a == b);
    }
    explicit operator bool() const
    {
        return *this != CCoinJoinBroadcastTx();
    }

    uint256 GetSignatureHash() const;

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyMasternode) const;
};

// base class
class CCoinJoinBaseSession
{
protected:
    mutable CCriticalSection cs_coinjoin;

    std::vector<CCoinJoinEntry> vecEntries; // Masternode/clients entries

    PoolState nState;                // should be one of the POOL_STATE_XXX values
    int64_t nTimeLastSuccessfulStep; // the time when last successful mixing step was performed

    int nSessionID; // 0 if no mixing session is active

    PartiallySignedTransaction finalPartiallySignedTransaction; // the finalized transaction ready for signing

    void SetNull();

public:
    CAmount nSessionDenom; //Users must submit at least one denom matching this

    CCoinJoinBaseSession() :
        vecEntries(),
        nState(POOL_STATE_IDLE),
        nTimeLastSuccessfulStep(0),
        nSessionID(0),
        finalPartiallySignedTransaction(),
        nSessionDenom(0)
    {
    }

    int GetState() const { return nState; }
    std::string GetStateString() const;

    bool CheckTransaction(PartiallySignedTransaction &psctxIn, CAmount& nFeeRet, PoolMessage& errRet, bool fUnsigned);

    int GetEntriesCount() const { return vecEntries.size(); }
};

// base class
class CCoinJoinBaseManager
{
protected:
    mutable CCriticalSection cs_vecqueue;

    // The current mixing sessions in progress on the network
    std::vector<CCoinJoinQueue> vecCoinJoinQueue;

    void SetNull();
    void CheckQueue(int nHeight);

public:
    CCoinJoinBaseManager() :
        vecCoinJoinQueue() {}

    int GetQueueSize() const { return vecCoinJoinQueue.size(); }
    bool GetQueueItem(CCoinJoinQueue& queueRet);
};

// helper class
class CCoinJoin
{
private:
    // make constructor, destructor and copying not available
    CCoinJoin() {}
    ~CCoinJoin() {}
    CCoinJoin(CCoinJoin const&) = delete;
    CCoinJoin& operator= (CCoinJoin const&) = delete;

public:
    static bool IsDenominatedAmount(CAmount nInputAmount);
    static CAmount GetDenomRange();
    static bool IsInDenomRange(const CAmount& nAmount);

    static std::string GetDenominationsToString(CAmount nDenom);

    static std::string GetMessageByID(PoolMessage nMessageID);

    /// Get the maximum number of transactions for the pool
    static unsigned int GetMaxPoolInputs() { return Params().PoolMaxInputs(); }
    static unsigned int GetMinPoolInputs() { return Params().PoolMinInputs(); }

    static CAmount GetMaxPoolAmount() { return COINJOIN_ENTRY_MAX_SIZE * COINJOIN_HIGH_DENOM; }
};

#endif //BITCOIN_MODULES_COINJOIN_COINJOIN_H
