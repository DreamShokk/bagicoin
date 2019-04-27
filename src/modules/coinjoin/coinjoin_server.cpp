// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <modules/coinjoin/coinjoin_server.h>

#include <modules/masternode/activemasternode.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <modules/masternode/masternode_sync.h>
#include <modules/masternode/masternode_man.h>
#include <modules/masternode/masternode_payments.h>
#include <netmessagemaker.h>
#include <scheduler.h>
#include <script/interpreter.h>
#include <shutdown.h>
#include <txmempool.h>
#include <util/system.h>
#include <util/moneystr.h>

#include <numeric>

CCoinJoinServer coinJoinServer;

void CCoinJoinServer::ProcessModuleMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman)
{
    if (!fMasternodeMode) return;
    if (fLiteMode) return; // ignore all CoinJoin related functionality
    if (!masternodeSync.IsBlockchainSynced()) return;

    if (strCommand == NetMsgType::CJACCEPT) {
        if (pfrom->GetSendVersion() < MIN_COINJOIN_PEER_PROTO_VERSION) {
            LogPrint(BCLog::CJOIN, "CJACCEPT -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_COINJOIN_PEER_PROTO_VERSION)));
            PushStatus(pfrom, STATUS_REJECTED, ERR_VERSION, connman);
            return;
        }
        CAmount nDenom;
        vRecv >> nDenom;

        if (IsSessionClosed()) {
            CloseQueue();
            if (IsSessionFull()) {
                // too many users in this session already, reject new ones
                LogPrintf("CJACCEPT -- queue is already full, trying to start a new one\n");
                PushStatus(pfrom, STATUS_ACCEPTED, ERR_QUEUE_FULL, connman);
                return;
            }
        }

        LogPrint(BCLog::CJOIN, "CJACCEPT -- nDenom %d\n", FormatMoney(nDenom));

        masternode_info_t mnInfo;
        if (!mnodeman.GetMasternodeInfo(activeMasternode.outpoint, mnInfo)) {
            PushStatus(pfrom, STATUS_REJECTED, ERR_MN_LIST, connman);
            return;
        }

        if (vecDenom.empty()) {
            LOCK(cs_vecqueue);
            for (const auto& q : vecCoinJoinQueue) {
                if (q.masternodeOutpoint == activeMasternode.outpoint) {
                    // refuse to create another queue this often
                    LogPrint(BCLog::CJOIN, "CJACCEPT -- last dsq is still in queue, refuse to mix\n");
                    PushStatus(pfrom, STATUS_REJECTED, ERR_RECENT, connman);
                    return;
                }
            }
        }

        PoolMessage nMessageID = MSG_NOERR;

        bool fResult = nSessionID == 0  ? CreateNewSession(nDenom, nMessageID, connman)
                                        : AddUserToExistingSession(nDenom, nMessageID);
        if (fResult) {
            LogPrintf("CJACCEPT -- is compatible, please submit!\n");
            PushStatus(pfrom, STATUS_ACCEPTED, nMessageID, connman);
            return;
        } else {
            LogPrintf("CJACCEPT -- not compatible with existing transactions!\n");
            PushStatus(pfrom, STATUS_REJECTED, nMessageID, connman);
            return;
        }

    } else if (strCommand == NetMsgType::CJQUEUE) {
        if (pfrom->GetSendVersion() < MIN_COINJOIN_PEER_PROTO_VERSION) {
            LogPrint(BCLog::CJOIN, "CJQUEUE -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_COINJOIN_PEER_PROTO_VERSION)));
            return;
        }

        CCoinJoinQueue queue;
        vRecv >> queue;

        if (queue.IsExpired(nCachedBlockHeight)) return;

        // process every queue only once
        LOCK(cs_vecqueue);
        for (std::vector<CCoinJoinQueue>::iterator it = vecCoinJoinQueue.begin(); it!=vecCoinJoinQueue.end(); ++it) {
            if (*it == queue) {
                LogPrint(BCLog::CJOIN, "CJQUEUE -- %s seen\n", queue.ToString());
                if (!it->fOpen) {
                    vecCoinJoinQueue.erase(it--);
                    queue.Relay(connman);
                }
                return;
            }
        }

        LogPrint(BCLog::CJOIN, "CJQUEUE -- %s new\n", queue.ToString());

        masternode_info_t mnInfo;
        if (!mnodeman.GetMasternodeInfo(queue.masternodeOutpoint, mnInfo)) return;

        if (!queue.CheckSignature(mnInfo.pubKeyMasternode)) {
            // we probably have outdated info
            mnodeman.AskForMN(pfrom, queue.masternodeOutpoint, connman);
            return;
        }

        if (!queue.fReady && queue.fOpen) {
            for (const auto& q : vecCoinJoinQueue) {
                if (q.masternodeOutpoint == queue.masternodeOutpoint) {
                    // no way same mn can send another "not yet ready" queue this soon
                    LogPrint(BCLog::CJOIN, "CJQUEUE -- Masternode %s is sending WAY too many queue messages\n", mnInfo.addr.ToString());
                    return;
                }
            }

            LogPrint(BCLog::CJOIN, "CJQUEUE -- new CoinJoin queue (%s) from masternode %s\n", queue.ToString(), mnInfo.addr.ToString());
            vecCoinJoinQueue.push_back(queue);
            queue.Relay(connman);
        }

    } else if (strCommand == NetMsgType::CJTXIN) {
        if (pfrom->GetSendVersion() < MIN_COINJOIN_PEER_PROTO_VERSION) {
            LogPrint(BCLog::CJOIN, "CJTXIN -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_COINJOIN_PEER_PROTO_VERSION)));
            PushStatus(pfrom, STATUS_REJECTED, ERR_VERSION, connman);
            return;
        }

        if (!CheckSessionMessage(POOL_STATE_ACCEPTING_ENTRIES, pfrom, connman)) return;

        CCoinJoinEntry entry;
        vRecv >> entry;
        entry.addr = pfrom->addr;

        CMutableTransaction mtx(*entry.psbtx.tx);

        LogPrint(BCLog::CJOIN, "CJTXIN -- from addr %s, vin size: %d, vout size: %d\n", entry.addr.ToStringIPPort(), mtx.vin.size(), mtx.vout.size());

        if (mtx.vin.size() > COINJOIN_ENTRY_MAX_SIZE) {
            LogPrintf("CJTXIN -- ERROR: too many inputs! %d/%d\n", mtx.vin.size(), COINJOIN_ENTRY_MAX_SIZE);
            PushStatus(pfrom, STATUS_REJECTED, ERR_MAXIMUM, connman);
            return;
        }

        if (mtx.vout.size() > COINJOIN_ENTRY_MAX_SIZE * 3) {
            LogPrintf("CJTXIN -- ERROR: too many outputs! %d/%d\n", mtx.vout.size(), COINJOIN_ENTRY_MAX_SIZE);
            PushStatus(pfrom, STATUS_REJECTED, ERR_MAXIMUM, connman);
            return;
        }

        CAmount nFee = 0;
        CAmount nMNfee = 0;
        PoolMessage nMessageID = MSG_NOERR;

        if (!CheckTransaction(entry.psbtx, nFee, nMessageID, true)) {
            LogPrintf("CJTXIN -- ERROR: CheckTransaction failed!\n");
            PushStatus(pfrom, STATUS_REJECTED, nMessageID, connman);
            return;
        }

        //run the basic checks - there must be at least one input and one output matching our session
        if (!IsCompatibleTxOut(mtx, nMNfee)) {
            LogPrintf("CJTXIN -- not compatible with existing transactions!\n");
            PushStatus(pfrom, STATUS_REJECTED, ERR_INVALID_OUT, connman);
            return;
        }

        if (nMNfee < nFee) {
            LogPrintf("CJTXIN -- missing masternode fees!\n");
            PushStatus(pfrom, STATUS_REJECTED, ERR_FEES, connman);
            return;
        }

        if (AddEntry(entry, nMessageID)) {
            PushStatus(pfrom, STATUS_ACCEPTED, nMessageID, connman);
            RelayStatus(STATUS_ACCEPTED, connman);
            CheckPool(connman);
        } else {
            PushStatus(pfrom, STATUS_REJECTED, nMessageID, connman);
        }

    } else if (strCommand == NetMsgType::CJSIGNFINALTX) {

        if (pfrom->GetSendVersion() < MIN_COINJOIN_PEER_PROTO_VERSION) {
            LogPrint(BCLog::CJOIN, "DSSIGNFINALTX -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_COINJOIN_PEER_PROTO_VERSION)));
            return;
        }

        if (!CheckSessionMessage(POOL_STATE_SIGNING, pfrom, connman)) return;

        PartiallySignedTransaction ptx(deserialize, vRecv);

        LogPrint(BCLog::CJOIN, "CJSIGNFINALTX -- received transaction %s from %s\n", ptx.tx->GetHash().ToString(), pfrom->addr.ToStringIPPort());

        LOCK(cs_coinjoin);
        // wrong transaction? just ignore it
        if (finalPartiallySignedTransaction.tx->GetHash() != ptx.tx->GetHash()) return;
        if (!finalPartiallySignedTransaction.Merge(ptx)) {
            // notify everyone else that this session should be terminated
            for (const auto& entry : vecEntries) {
                connman->ForNode(entry.addr, [&connman, this](CNode* pnode) {
                    PushStatus(pnode, STATUS_REJECTED, MSG_NOERR, connman);
                    return true;
                });
            }
            SetNull();
        }
        // see if we are ready to submit
        CAmount nFee = 0;
        PoolMessage nMessageID = MSG_NOERR;
        if (CheckTransaction(finalPartiallySignedTransaction, nFee, nMessageID, false)) {
            CommitFinalTransaction(connman);
        }
    }
}

bool CCoinJoinServer::CheckSessionMessage(PoolState state, CNode* pfrom, CConnman* connman) {
    // right state?
    if (GetState() != state) { // our queue but already closed
        LogPrintf("CCoinJoinServer::CheckSessionMessage -- incorrect pool state!\n");
        PushStatus(pfrom, STATUS_REJECTED, ERR_SESSION, connman);
        return false;
    }
    // make sure it's really our session
    LOCK(cs_vecqueue);
    for (std::vector<CCoinJoinQueue>::iterator it = vecCoinJoinQueue.begin(); it!=vecCoinJoinQueue.end(); ++it) {
        if (it!=vecCoinJoinQueue.end() && it->masternodeOutpoint == activeMasternode.outpoint) {
            if (it->fOpen == it->fReady) { // our queue but already closed
                LogPrintf("CCoinJoinServer::CheckSessionMessage -- queue not ready or open!\n");
                PushStatus(pfrom, STATUS_REJECTED, ERR_SESSION, connman);
                return false;
            }
            break;
        }  // queue already removed
        LogPrintf("CCoinJoinServer::CheckSessionMessage -- session removed!\n");
        PushStatus(pfrom, STATUS_REJECTED, ERR_SESSION, connman);
        return false;
    }

    //do we have enough users in the current session?
    if (!IsSessionReady()) {
        LogPrintf("CCoinJoinServer::CheckSessionMessage -- session not ready!\n");
        PushStatus(pfrom, STATUS_REJECTED, ERR_SESSION, connman);
        return false;
    }
    return true;
}

void CCoinJoinServer::CloseQueue()
{
    LOCK(cs_vecqueue);
    // notify the network about the closed queue
    for (std::vector<CCoinJoinQueue>::iterator it = vecCoinJoinQueue.begin(); it!=vecCoinJoinQueue.end(); ++it) {
        if (it!=vecCoinJoinQueue.end() && it->masternodeOutpoint == activeMasternode.outpoint) {
            if (!it->IsExpired(nCachedBlockHeight)) {
                CCoinJoinQueue queue(*it);
                queue.fOpen = false;
                queue.Sign();
                queue.Relay(g_connman.get());
            }
            vecCoinJoinQueue.erase(it);
            break;
        }
    }
}


void CCoinJoinServer::SetNull()
{
    // MN side
    CloseQueue();

    LOCK(cs_vecqueue);

    vecDenom.clear();
    CCoinJoinBaseSession::SetNull();
    CCoinJoinBaseManager::SetNull();
}

//
// Check the mixing progress and send client updates if a Masternode
//
void CCoinJoinServer::CheckPool(CConnman* connman)
{
    if (!fMasternodeMode) return;

    LogPrint(BCLog::CJOIN, "CCoinJoinServer::CheckPool -- entries count %lu\n", GetEntriesCount());

    // If entries are full, create finalized transaction
    // wait a while for all to join, otherwise just go ahead
    bool fReady = false;
    if (static_cast<unsigned int>(GetEntriesCount()) >= vecDenom.size()) fReady = true;
    if (GetTime() - nTimeLastSuccessfulStep >= COINJOIN_ACCEPT_TIMEOUT && static_cast<unsigned int>(GetEntriesCount()) >= CCoinJoin::GetMinPoolInputs()) fReady = true;

    if (GetState() == POOL_STATE_ACCEPTING_ENTRIES && fReady) {
        // close our not-ready queue. Note: vecCoinJoinQueue is in chronological order, the ready queue remains
        CloseQueue();
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::CheckPool -- FINALIZE TRANSACTIONS\n");
        SetState(POOL_STATE_SIGNING);
        CreateFinalTransaction(connman);
        return;
    }
}

void CCoinJoinServer::CreateFinalTransaction(CConnman* connman)
{
    LogPrint(BCLog::CJOIN, "CCoinJoinServer::CreateFinalTransaction -- FINALIZE TRANSACTIONS\n");

    LOCK(cs_coinjoin);
    finalPartiallySignedTransaction = PartiallySignedTransaction();
    CMutableTransaction mtx;

    for (auto& entry : vecEntries) {
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::CreateFinalTransaction -- processing entry:%s\n", entry.addr.ToStringIPPort());
        for (unsigned int i = 0; i < entry.psbtx.tx->vin.size(); ++i) {
            mtx.vin.push_back(entry.psbtx.tx->vin[i]);
            mtx.vin[i].scriptSig.clear();
            mtx.vin[i].scriptWitness.SetNull();
        }
        for (unsigned int i = 0; i < entry.psbtx.tx->vout.size(); ++i) {
            mtx.vout.push_back(entry.psbtx.tx->vout[i]);
        }
    }

    Shuffle(mtx.vin.begin(), mtx.vin.end(), FastRandomContext());
    Shuffle(mtx.vout.begin(), mtx.vout.end(), FastRandomContext());

    finalPartiallySignedTransaction.tx = mtx;

    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        finalPartiallySignedTransaction.inputs.push_back(PSBTInput());
    }
    for (unsigned int i = 0; i < mtx.vout.size(); ++i) {
        finalPartiallySignedTransaction.outputs.push_back(PSBTOutput());
    }

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : finalPartiallySignedTransaction.tx->vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    // Fill the inputs
    for (unsigned int i = 0; i < finalPartiallySignedTransaction.tx->vin.size(); ++i) {
        PSBTInput& input = finalPartiallySignedTransaction.inputs.at(i);

        if (input.non_witness_utxo || !input.witness_utxo.IsNull()) {
            continue;
        }

        const Coin& coin = view.AccessCoin(finalPartiallySignedTransaction.tx->vin[i].prevout);

        std::vector<std::vector<unsigned char>> solutions_data;
        txnouttype which_type = Solver(coin.out.scriptPubKey, solutions_data);
        if (which_type == TX_WITNESS_V0_SCRIPTHASH || which_type == TX_WITNESS_V0_KEYHASH || which_type == TX_WITNESS_UNKNOWN) {
            input.witness_utxo = coin.out;
        }
    }

    LogPrint(BCLog::CJOIN, "CCoinJoinServer::CreateFinalTransaction -- finalPartiallySignedTransaction=%s\n",
             finalPartiallySignedTransaction.tx->GetHash().ToString());
    RelayFinalTransaction(finalPartiallySignedTransaction, connman);
}

void CCoinJoinServer::CommitFinalTransaction(CConnman* connman)
{
    if (!fMasternodeMode) return; // check and relay final tx only on masternode

    CMutableTransaction mtxFinal;
    if (!FinalizeAndExtractPSBT(finalPartiallySignedTransaction, mtxFinal)) {
        LogPrintf("CCoinJoinServer::CommitFinalTransaction -- FinalizeAndExtractPSBT() error: Transaction not final\n");
        SetNull();
        // not much we can do in this case, just notify clients
        RelayCompletedTransaction(ERR_INVALID_TX, connman);
        return;
    }

    CTransactionRef finalTransaction = MakeTransactionRef(mtxFinal);
    uint256 hashTx = finalTransaction->GetHash();

    LogPrint(BCLog::CJOIN, "CCoinJoinServer::CommitFinalTransaction -- finalTransaction=%s\n", finalTransaction->ToString());

    CValidationState validationState;

    {
        // See if the transaction is valid, don't run in dummy mode if we want to mine it
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, validationState, finalTransaction, nullptr, nullptr, false, maxTxFee, false))
        {
            LogPrintf("CCoinJoinServer::CommitFinalTransaction -- AcceptToMemoryPool() error: Transaction not valid\n");
            SetNull();
            // not much we can do in this case, just notify clients
            RelayCompletedTransaction(ERR_INVALID_TX, connman);
            return;
        }
    }

    LogPrintf("CCoinJoinServer::CommitFinalTransaction -- TRANSMITTING PSBT\n");

    CInv inv(MSG_TX, hashTx);
    connman->RelayInv(inv);

    // Tell the clients it was successful
    RelayCompletedTransaction(MSG_SUCCESS, connman);

    // Reset
    LogPrint(BCLog::CJOIN, "CCoinJoinServer::CommitFinalTransaction -- COMPLETED -- RESETTING\n");
    SetNull();
}
/*
//
// Ban clients a fee if they're abusive
//
void CCoinJoinServer::BanAbusive(CConnman* connman)
{
    if (!fMasternodeMode) return;

    //we don't need to charge collateral for every offence.
    if (GetRandInt(100) > 33) return;

    std::vector<CTransactionRef> vecOffendersCollaterals;

    if (nState == POOL_STATE_ACCEPTING_ENTRIES) {
        for (const auto& txCollateral : vecSessionCollaterals) {
            bool fFound = false;
            for (const auto& entry : vecEntries)
                if (*entry.txCollateral == *txCollateral)
                    fFound = true;

            // This queue entry didn't send us the promised transaction
            if (!fFound) {
                LogPrintf("CCoinJoinServer::ChargeFees -- found uncooperative node (didn't send transaction), found offence\n");
                vecOffendersCollaterals.push_back(txCollateral);
            }
        }
    }

    if (nState == POOL_STATE_SIGNING) {
        // who didn't sign?
        for (const auto& entry : vecEntries) {
            for (const auto& txdsin : entry.vecTxDSIn) {
                if (!txdsin.fHasSig) {
                    LogPrintf("CCoinJoinServer::ChargeFees -- found uncooperative node (didn't sign), found offence\n");
                    vecOffendersCollaterals.push_back(entry.txCollateral);
                }
            }
        }
    }

    // no offences found
    if (vecOffendersCollaterals.empty()) return;

    //mostly offending? Charge sometimes
    if ((int)vecOffendersCollaterals.size() >= Params().PoolMaxInputs() - 1 && GetRandInt(100) > 33) return;

    //everyone is an offender? That's not right
    if ((int)vecOffendersCollaterals.size() >= Params().PoolMaxInputs()) return;

    //charge one of the offenders randomly
    Shuffle(vecOffendersCollaterals.begin(), vecOffendersCollaterals.end(), FastRandomContext());

    if (nState == POOL_STATE_ACCEPTING_ENTRIES || nState == POOL_STATE_SIGNING) {
        LogPrintf("CCoinJoinServer::ChargeFees -- found uncooperative node (didn't %s transaction), charging fees: %s\n",
                (nState == POOL_STATE_SIGNING) ? "sign" : "send", vecOffendersCollaterals[0]->ToString());

        LOCK(cs_main);

        CValidationState state;
        if (!AcceptToMemoryPool(mempool, state, vecOffendersCollaterals[0], nullptr, nullptr, false, maxTxFee)) {
            // should never really happen
            LogPrintf("CCoinJoinServer::ChargeFees -- ERROR: AcceptToMemoryPool failed!\n");
        } else {
            if (connman) {
                CInv inv(MSG_TX, vecOffendersCollaterals[0]->GetHash());
                connman->ForEachNode([&inv](CNode* pnode)
                {
                    pnode->PushInventory(inv);
                });
            }
        }
    }
}
*/
//
// Check for various timeouts (queue objects, mixing, etc)
//
void CCoinJoinServer::CheckTimeout(int nHeight)
{
    if (!fMasternodeMode) return;

    CheckQueue(nHeight);

    int nTimeout = (nState == POOL_STATE_SIGNING) ? COINJOIN_SIGNING_TIMEOUT : COINJOIN_QUEUE_TIMEOUT;
    bool fTimeout = GetTime() - nTimeLastSuccessfulStep >= nTimeout;

    if (nState != POOL_STATE_IDLE && fTimeout) {
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::CheckTimeout -- %s timed out (%ds) -- resetting\n",
                (nState == POOL_STATE_SIGNING) ? "Signing" : "Session", nTimeout);
        // BanAbusive(connman);
        SetNull();
    }
}

/*
    Check to see if we're ready for submissions from clients
    After receiving multiple cja messages, the queue will switch to "accepting entries"
    which is the active state right before merging the transaction
*/
void CCoinJoinServer::CheckForCompleteQueue(CConnman* connman)
{
    if (!fMasternodeMode) return;

    if (nState == POOL_STATE_QUEUE && IsSessionReady()) {
        SetState(POOL_STATE_ACCEPTING_ENTRIES);
        CCoinJoinQueue queue(nSessionDenom, activeMasternode.outpoint, nCachedBlockHeight, true, false);
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::CheckForCompleteQueue -- queue is ready, signing and relaying (%s)\n", queue.ToString());
        queue.Sign();
        LOCK(cs_vecqueue);
        vecCoinJoinQueue.push_back(queue);
        queue.Relay(connman);
    }
}

//
// Add a clients transaction to the pool
//
bool CCoinJoinServer::AddEntry(const CCoinJoinEntry& entryNew, PoolMessage& nMessageIDRet)
{
    if (!fMasternodeMode) return false;

    if (static_cast<unsigned int>(GetEntriesCount()) >= CCoinJoin::GetMaxPoolInputs() || GetState() != POOL_STATE_ACCEPTING_ENTRIES) {
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::AddEntry -- entries is full!\n");
        nMessageIDRet = ERR_ENTRIES_FULL;
        return false;
    }

    vecEntries.push_back(entryNew);

    LogPrint(BCLog::CJOIN, "CCoinJoinServer::AddEntry -- adding entry\n");
    nMessageIDRet = MSG_ENTRIES_ADDED;
    nTimeLastSuccessfulStep = GetTime();

    return true;
}

bool CCoinJoinServer::IsCompatibleTxOut(const CMutableTransaction mtx, CAmount& nMNfee)
{
    CScript payee;

    if (mnpayments.GetBlockPayee(mtx.nLockTime, payee)) {
        CTxDestination address;
        ExtractDestination(payee, address);
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::IsCompatibleTxOut --- found masternode payee = %s\n", EncodeDestination(address));
    }

    for (const auto& entry : mtx.vout) {
        if (!CCoinJoin::IsDenominatedAmount(entry.nValue)) {
            LogPrintf("CCoinJoinServer::IsCompatibleTxOut --- ERROR: non-denom output = %d\n", entry.nValue);
            return false;
        }
        if (entry.scriptPubKey == payee) nMNfee += entry.nValue;
    }

    return true;
}

bool CCoinJoinServer::CreateNewSession(const CAmount& nDenom, PoolMessage& nMessageIDRet, CConnman* connman)
{
    if (!fMasternodeMode || nSessionID != 0) return false;

    LOCK(cs_coinjoin);

    // new session can only be started in idle mode
    if (nState != POOL_STATE_IDLE) {
        nMessageIDRet = ERR_MODE;
        LogPrintf("CCoinJoinServer::CreateNewSession -- incompatible mode: nState=%d\n", nState);
        return false;
    }

    if (!CCoinJoin::IsInDenomRange(nDenom)) {
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::%s -- denom not valid!\n", __func__);
        nMessageIDRet = ERR_DENOM;
        return false;
    }

    // start new session
    nMessageIDRet = MSG_NOERR;
    nSessionID = GetRandInt(999999)+1;
    nSessionDenom = nDenom;

    SetState(POOL_STATE_QUEUE);
    nTimeLastSuccessfulStep = GetTime();

    if (!fUnitTest) {
        //broadcast that I'm accepting entries, only if it's the first entry through
        CCoinJoinQueue queue(nDenom, activeMasternode.outpoint, nCachedBlockHeight, false, true);
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::CreateNewSession -- signing and relaying new queue: %s\n", queue.ToString());
        queue.Sign();
        LOCK(cs_vecqueue);
        vecCoinJoinQueue.push_back(queue);
        queue.Relay(connman);
    }

    vecDenom.push_back(nSessionDenom);
    LogPrintf("CCoinJoinServer::CreateNewSession -- new session created, nSessionID: %d  nSessionDenom: %d (%s)  vecDenom.size(): %d\n",
            nSessionID, nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom), vecDenom.size());

    return true;
}

bool CCoinJoinServer::AddUserToExistingSession(const CAmount& nDenom, PoolMessage& nMessageIDRet)
{
    if (!fMasternodeMode || nSessionID == 0) return false;

    LOCK(cs_coinjoin);

    // we only add new users to an existing session when we are in queue mode
    if (nState != POOL_STATE_QUEUE) {
        nMessageIDRet = ERR_MODE;
        LogPrintf("CCoinJoinServer::AddUserToExistingSession -- incompatible mode: nState=%d\n", nState);
        return false;
    }

    if (!CCoinJoin::IsInDenomRange(nDenom)) {
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::%s -- denom not valid!\n", __func__);
        nMessageIDRet = ERR_DENOM;
        return false;
    }

    if ((nSessionDenom ^ nDenom) == (nSessionDenom | nDenom)) {
        LogPrintf("CCoinJoinServer::AddUserToExistingSession -- incompatible denom %d (%s) != nSessionDenom %d (%s)\n",
                    nDenom, CCoinJoin::GetDenominationsToString(nDenom), nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom));
        nMessageIDRet = ERR_DENOM;
        return false;
    }

    // count new user as accepted to an existing session

    nMessageIDRet = MSG_NOERR;
    nSessionDenom |= nDenom;
    nTimeLastSuccessfulStep = GetTime();
    vecDenom.push_back(nSessionDenom);

    LogPrintf("CCoinJoinServer::AddUserToExistingSession -- new user accepted, nSessionID: %d  nSessionDenom: %d (%s)  vecSessionCollaterals.size(): %d\n",
            nSessionID, nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom), vecDenom.size());

    return true;
}

void CCoinJoinServer::RelayFinalTransaction(const PartiallySignedTransaction& txFinal, CConnman* connman)
{
    LogPrint(BCLog::CJOIN, "CCoinJoinServer::%s -- nSessionID: %d  nSessionDenom: %d (%s)\n",
            __func__, nSessionID, nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom));

    CCoinJoinBroadcastTx finalTx(nSessionID, txFinal, activeMasternode.outpoint, GetAdjustedTime());
    finalTx.Sign();

    // final mixing tx with empty signatures should be relayed to mixing participants only
    bool allOK = true;
    for (std::vector<CCoinJoinEntry>::iterator it = vecEntries.begin(); it != vecEntries.end(); ++it) {
        bool fOk = connman->ForNode(it->addr, [&finalTx, &connman](CNode* pnode) {
            CNetMsgMaker msgMaker(pnode->GetSendVersion());
            connman->PushMessage(pnode, msgMaker.Make(NetMsgType::CJFINALTX, finalTx));
            return true;
        });
        if (!fOk) {
            // no such node? maybe this client disconnected or our own connection went down
            LogPrintf("CCoinJoinServer::%s -- client(s) disconnected, removing entry: %s nSessionID: %d  nSessionDenom: %d (%s)\n",
                    __func__, it->addr.ToStringIPPort(), nSessionID, nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom));
            vecEntries.erase(it--);
            allOK = false;
        }
    }
    if (allOK) return;
    if (vecEntries.size() >= CCoinJoin::GetMinPoolInputs()) {
        CreateFinalTransaction(connman);
    } else SetNull();
}

void CCoinJoinServer::PushStatus(CNode* pnode, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID, CConnman* connman)
{
    if (!pnode) return;
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman->PushMessage(pnode, msgMaker.Make(NetMsgType::CJSTATUSUPDATE, nSessionID, (int)nState, (int)vecEntries.size(), (int)nStatusUpdate, (int)nMessageID));
}

void CCoinJoinServer::RelayStatus(PoolStatusUpdate nStatusUpdate, CConnman* connman, PoolMessage nMessageID)
{
    // status updates should be relayed to mixing participants only
    for (std::vector<CCoinJoinEntry>::iterator it = vecEntries.begin(); it != vecEntries.end(); ++it) {
        // make sure everyone is still connected
        bool fOk = connman->ForNode(it->addr, [&nStatusUpdate, &nMessageID, &connman, this](CNode* pnode) {
            PushStatus(pnode, nStatusUpdate, nMessageID, connman);
            return true;
        });
        if (!fOk) {
            // no such node? maybe this client disconnected or our own connection went down
            LogPrintf("CCoinJoinServer::%s -- client(s) disconnected, removing entry: %s nSessionID: %d  nSessionDenom: %d (%s)\n",
                    __func__, it->addr.ToStringIPPort(), nSessionID, nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom));
            vecEntries.erase(it--);
        }
    }

    if (vecEntries.empty()) {
        // all clients disconnected, there is probably some issues with our own connection
        // do not ban anyone, just reset the pool
        SetNull();
    }
}

void CCoinJoinServer::RelayCompletedTransaction(PoolMessage nMessageID, CConnman* connman)
{
    LogPrint(BCLog::CJOIN, "CCoinJoinServer::%s -- nSessionID: %d  nSessionDenom: %d (%s)\n",
            __func__, nSessionID, nSessionDenom, CCoinJoin::GetDenominationsToString(nSessionDenom));

    // final mixing tx with empty signatures should be relayed to mixing participants only
    for (const auto& entry : vecEntries) {
        connman->ForNode(entry.addr, [&nMessageID, &connman, this](CNode* pnode) {
            CNetMsgMaker msgMaker(pnode->GetSendVersion());
            connman->PushMessage(pnode, msgMaker.Make(NetMsgType::CJCOMPLETE, nSessionID, (int)nMessageID));
            return true;
        });
    }
}

void CCoinJoinServer::SetState(PoolState nStateNew)
{
    if (!fMasternodeMode) return;

    if (nStateNew == POOL_STATE_ERROR || nStateNew == POOL_STATE_SUCCESS) {
        LogPrint(BCLog::CJOIN, "CCoinJoinServer::SetState -- Can't set state to ERROR or SUCCESS as a Masternode. \n");
        return;
    }

    LogPrintf("CCoinJoinServer::SetState -- nState: %d, nStateNew: %d\n", nState, nStateNew);
    nState = nStateNew;
}

void CCoinJoinServer::UpdatedBlockTip(const CBlockIndex *pindexNew) {
    if (ShutdownRequested()) return;
    if (fLiteMode) return; // disable all specific functionality
    if (!fMasternodeMode) return; // only run on masternodes

    nCachedBlockHeight = pindexNew->nHeight;
    LogPrint(BCLog::CJOIN, "CCoinJoinServer::UpdatedBlockTip -- nCachedBlockHeight: %d\n", nCachedBlockHeight);

    if (!masternodeSync.IsBlockchainSynced())
        return;

    CheckPool(g_connman.get());
    CheckTimeout(nCachedBlockHeight);
}

void CCoinJoinServer::ClientTask(CConnman* connman)
{
    if (fLiteMode) return; // disable all specific functionality
    if (!fMasternodeMode) return; // only run on masternodes

    if (!masternodeSync.IsBlockchainSynced() || ShutdownRequested())
        return;

    CheckForCompleteQueue(connman);
}

void CCoinJoinServer::Controller(CScheduler& scheduler, CConnman* connman)
{
    if (!fLiteMode) {
        scheduler.scheduleEvery(std::bind(&CCoinJoinServer::ClientTask, this, connman), 1000);
    }
}
