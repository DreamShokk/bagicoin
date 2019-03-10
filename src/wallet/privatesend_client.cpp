// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/privatesend_client.h>

#include <consensus/validation.h>
#include <modules/masternode/masternode_payments.h>
#include <modules/masternode/masternode_sync.h>
#include <modules/masternode/masternode_man.h>
#include <netmessagemaker.h>
#include <reverse_iterator.h>
#include <scheduler.h>
#include <script/sign.h>
#include <shutdown.h>
#include <txmempool.h>
#include <util/system.h>
#include <util/moneystr.h>
#include <wallet/coincontrol.h>

#include <memory>

void CKeyHolderStorage::AddKey(std::shared_ptr<CReserveScript>& script, CWallet* pwalletIn)
{
    OutputType output_type = pwalletIn->m_default_change_type != OutputType::CHANGE_AUTO ? pwalletIn->m_default_change_type : pwalletIn->m_default_address_type;
    std::shared_ptr<CReserveKey> reservekey = std::make_shared<CReserveKey>(pwalletIn);;
    CPubKey vchPubKey;
    if (!reservekey->GetReservedKey(vchPubKey)) {
        LogPrintf("CKeyHolderStorage::%s -- Warning: Keypool ran out, trying to top up\n", __func__);
        pwalletIn->TopUpKeyPool();
        if (!reservekey->GetReservedKey(vchPubKey)) {
            LogPrintf("CKeyHolderStorage::%s -- Error: Failed to obtain key from keypool\n", __func__);
            return;
        }
    }
    pwalletIn->LearnRelatedScripts(vchPubKey, output_type);

    script->reserveScript = GetScriptForDestination(GetDestinationForKey(vchPubKey, output_type));

    LOCK(cs_storage);
    storage.emplace_back(std::move(reservekey));
    LogPrintf("CKeyHolderStorage::%s -- storage size %lld\n", __func__, storage.size());
}

void CKeyHolderStorage::KeepAll()
{
    // don't hold cs_storage while calling KeepKey(), which might lock cs_wallet
    LOCK(cs_storage);

    if (storage.size() > 0) {
        for (auto &key : storage) {
            key->KeepKey();
        }
        LogPrintf("CKeyHolderStorage::%s -- %lld keys kept\n", __func__, storage.size());
    }
}

void CKeyHolderStorage::ReturnAll()
{
    // don't hold cs_storage while calling ReturnKey(), which might lock cs_wallet
    LOCK(cs_storage);

    if (storage.size() > 0) {
        for (auto &key : storage) {
            key->ReturnKey();
        }
        LogPrintf("CKeyHolderStorage::%s -- %lld keys returned\n", __func__, storage.size());
    }
}

void CPrivateSendClientManager::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman)
{
    if (fLiteMode) return; // ignore all Chaincoin related functionality
    if (!masternodeSync.IsBlockchainSynced()) return;

    if (!CheckDiskSpace()) {
        ResetPool();
        fEnablePrivateSend = false;
        strAutoDenomResult = _("WARNING: Low disk space, disabling PrivateSend.");
        LogPrintf("CPrivateSendClientManager::ProcessMessage -- Not enough disk space, disabling PrivateSend.\n");
        return;
    }

    if (strCommand == NetMsgType::DSQUEUE) {
        if (pfrom->GetSendVersion() < MIN_PRIVATESEND_PEER_PROTO_VERSION) {
            LogPrint(BCLog::PRIVSEND, "DSQUEUE -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PRIVATESEND_PEER_PROTO_VERSION)));
            return;
        }

        CPrivateSendQueue dsq;
        vRecv >> dsq;

        {
            TRY_LOCK(cs_vecqueue, lockRecv);
            if (!lockRecv) return;

            // process every dsq only once
            for (const auto& q : vecPrivateSendQueue) {
                if (q == dsq) {
                    // LogPrint("privatesend", "DSQUEUE -- %s seen\n", dsq.ToString());
                    return;
                }
            }
        } // cs_vecqueue

        LogPrint(BCLog::PRIVSEND, "DSQUEUE -- %s new\n", dsq.ToString());

        if (dsq.IsExpired()) return;

        masternode_info_t infoMn;
        if (!mnodeman.GetMasternodeInfo(dsq.masternodeOutpoint, infoMn)) return;

        if (!dsq.CheckSignature(infoMn.pubKeyMasternode)) {
            // we probably have outdated info
            mnodeman.AskForMN(pfrom, dsq.masternodeOutpoint, connman);
            return;
        }

        // if the queue is ready, submit if we can
        if (dsq.fReady) {
            LOCK(cs_deqsessions);
            for (auto& session : deqSessions) {
                masternode_info_t mnMixing;
                if (session.GetMixingMasternodeInfo(mnMixing) && mnMixing.addr == infoMn.addr && session.GetState() == POOL_STATE_QUEUE) {
                    LogPrint(BCLog::PRIVSEND, "DSQUEUE -- PrivateSend queue (%s) is ready on masternode %s\n", dsq.ToString(), infoMn.addr.ToString());
                    session.SubmitDenominate();
                    return;
                }
            }
        } else {
            LOCK(cs_deqsessions); // have to lock this first to avoid deadlocks with cs_vecqueue
            TRY_LOCK(cs_vecqueue, lockRecv);
            if (!lockRecv) return;

            for (const auto& q : vecPrivateSendQueue) {
                if (q.masternodeOutpoint == dsq.masternodeOutpoint) {
                    // no way same mn can send another "not yet ready" dsq this soon
                    LogPrint(BCLog::PRIVSEND, "DSQUEUE -- Masternode %s is sending WAY too many dsq messages\n", infoMn.addr.ToString());
                    return;
                }
            }

            int nThreshold = infoMn.nLastDsq + mnodeman.CountMasternodes() / 5;
            LogPrint(BCLog::PRIVSEND, "DSQUEUE -- nLastDsq: %d  threshold: %d  nDsqCount: %d\n", infoMn.nLastDsq, nThreshold, mnodeman.nDsqCount);
            //don't allow a few nodes to dominate the queuing process
            if (infoMn.nLastDsq != 0 && nThreshold > mnodeman.nDsqCount) {
                LogPrint(BCLog::PRIVSEND, "DSQUEUE -- Masternode %s is sending too many dsq messages\n", infoMn.addr.ToString());
                return;
            }

            if (!mnodeman.AllowMixing(dsq.masternodeOutpoint)) return;

            LogPrint(BCLog::PRIVSEND, "DSQUEUE -- new PrivateSend queue (%s) from masternode %s\n", dsq.ToString(), infoMn.addr.ToString());
            for (auto& session : deqSessions) {
                masternode_info_t mnMixing;
                if (session.GetMixingMasternodeInfo(mnMixing) && mnMixing.outpoint == dsq.masternodeOutpoint) {
                    dsq.fTried = true;
                }
            }
            vecPrivateSendQueue.push_back(dsq);
            dsq.Relay(connman);
        }

    } else if (
        strCommand == NetMsgType::DSSTATUSUPDATE ||
        strCommand == NetMsgType::DSFINALTX ||
        strCommand == NetMsgType::DSCOMPLETE) {
        LOCK(cs_deqsessions);
        for (auto& session : deqSessions) {
            session.ProcessMessage(pfrom, strCommand, vRecv, connman);
        }
    }
}

void CPrivateSendClientSession::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman)
{
    if (fLiteMode) return; // ignore all Dash related functionality
    if (!masternodeSync.IsBlockchainSynced()) return;

    if (strCommand == NetMsgType::DSSTATUSUPDATE) {

        if (pfrom->GetSendVersion() < MIN_PRIVATESEND_PEER_PROTO_VERSION) {
            LogPrint(BCLog::PRIVSEND, "DSSTATUSUPDATE -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PRIVATESEND_PEER_PROTO_VERSION)));
            return;
        }

        if (!infoMixingMasternode.fInfoValid) return;
        if (infoMixingMasternode.addr != pfrom->addr) {
            //LogPrintf("DSSTATUSUPDATE -- message doesn't match current Masternode: infoMixingMasternode %s addr %s\n", infoMixingMasternode.addr.ToString(), pfrom->addr.ToString());
            return;
        }

        int nMsgSessionID;
        int nMsgState;
        int nMsgEntriesCount;
        int nMsgStatusUpdate;
        int nMsgMessageID;
        vRecv >> nMsgSessionID >> nMsgState >> nMsgEntriesCount >> nMsgStatusUpdate >> nMsgMessageID;

        if (nMsgState < POOL_STATE_MIN || nMsgState > POOL_STATE_MAX) {
            LogPrint(BCLog::PRIVSEND, "DSSTATUSUPDATE -- nMsgState is out of bounds: %d\n", nMsgState);
            return;
        }

        if (nMsgStatusUpdate < STATUS_REJECTED || nMsgStatusUpdate > STATUS_ACCEPTED) {
            LogPrint(BCLog::PRIVSEND, "DSSTATUSUPDATE -- nMsgStatusUpdate is out of bounds: %d\n", nMsgStatusUpdate);
            return;
        }

        if (nMsgMessageID < MSG_POOL_MIN || nMsgMessageID > MSG_POOL_MAX) {
            LogPrint(BCLog::PRIVSEND, "DSSTATUSUPDATE -- nMsgMessageID is out of bounds: %d\n", nMsgMessageID);
            return;
        }

        LogPrint(BCLog::PRIVSEND, "DSSTATUSUPDATE -- nMsgSessionID %d  nMsgState: %d  nEntriesCount: %d  nMsgStatusUpdate: %d  nMsgMessageID %d (%s)\n",
                nMsgSessionID, nMsgState, nEntriesCount, nMsgStatusUpdate, nMsgMessageID, CPrivateSend::GetMessageByID(PoolMessage(nMsgMessageID)));

        if (!CheckPoolStateUpdate(PoolState(nMsgState), nMsgEntriesCount, PoolStatusUpdate(nMsgStatusUpdate), PoolMessage(nMsgMessageID), nMsgSessionID)) {
            LogPrint(BCLog::PRIVSEND, "DSSTATUSUPDATE -- CheckPoolStateUpdate failed\n");
        }

    } else if (strCommand == NetMsgType::DSFINALTX) {
        if (pfrom->GetSendVersion() < MIN_PRIVATESEND_PEER_PROTO_VERSION) {
            LogPrint(BCLog::PRIVSEND, "DSFINALTX -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PRIVATESEND_PEER_PROTO_VERSION)));
            return;
        }

        if (!infoMixingMasternode.fInfoValid) return;
        if (infoMixingMasternode.addr != pfrom->addr) {
            LogPrintf("DSFINALTX -- message doesn't match current Masternode: infoMixingMasternode %s addr %s\n", infoMixingMasternode.addr.ToString(), pfrom->addr.ToString());
            return;
        }

        int nMsgSessionID;
        vRecv >> nMsgSessionID;
        CTransaction txNew(deserialize, vRecv);

        if (nSessionID != nMsgSessionID) {
            LogPrint(BCLog::PRIVSEND, "DSFINALTX -- message doesn't match current PrivateSend session: nSessionID: %d  nMsgSessionID: %d\n", nSessionID, nMsgSessionID);
            return;
        }

        LogPrint(BCLog::PRIVSEND, "DSFINALTX -- txNew %s\n", txNew.ToString());

        //check to see if input is spent already? (and probably not confirmed)
        SignFinalTransaction(txNew, pfrom);

    } else if (strCommand == NetMsgType::DSCOMPLETE) {
        if (pfrom->GetSendVersion() < MIN_PRIVATESEND_PEER_PROTO_VERSION) {
            LogPrint(BCLog::PRIVSEND, "DSCOMPLETE -- peer=%d using obsolete version %i\n", pfrom->GetId(), pfrom->GetSendVersion());
            connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PRIVATESEND_PEER_PROTO_VERSION)));
            return;
        }

        if (!infoMixingMasternode.fInfoValid) return;
        if (infoMixingMasternode.addr != pfrom->addr) {
            LogPrint(BCLog::PRIVSEND, "DSCOMPLETE -- message doesn't match current Masternode: infoMixingMasternode=%s  addr=%s\n", infoMixingMasternode.addr.ToString(), pfrom->addr.ToString());
            return;
        }

        int nMsgSessionID;
        int nMsgMessageID;
        vRecv >> nMsgSessionID >> nMsgMessageID;

        if (nMsgMessageID < MSG_POOL_MIN || nMsgMessageID > MSG_POOL_MAX) {
            LogPrint(BCLog::PRIVSEND, "DSCOMPLETE -- nMsgMessageID is out of bounds: %d\n", nMsgMessageID);
            return;
        }

        if (nSessionID != nMsgSessionID) {
            LogPrint(BCLog::PRIVSEND, "DSCOMPLETE -- message doesn't match current PrivateSend session: nSessionID: %d  nMsgSessionID: %d\n", nSessionID, nMsgSessionID);
            return;
        }

        LogPrint(BCLog::PRIVSEND, "DSCOMPLETE -- nMsgSessionID %d  nMsgMessageID %d (%s)\n", nMsgSessionID, nMsgMessageID, CPrivateSend::GetMessageByID(PoolMessage(nMsgMessageID)));

        CompletedTransaction(PoolMessage(nMsgMessageID));
    }
}

void CPrivateSendClientSession::ResetPool()
{
    txMyCollateral = CMutableTransaction();
    UnlockCoins();
    keyHolderStorage.ReturnAll();
    SetNull();
}

void CPrivateSendClientManager::ResetPool()
{
    LOCK(cs_deqsessions);
    nCachedLastSuccessBlock = 0;
    vecMasternodesUsed.clear();
    for (auto& session : deqSessions) {
        session.ResetPool();
    }
    deqSessions.clear();
}

void CPrivateSendClientSession::SetNull()
{
    // Client side
    nEntriesCount = 0;
    fLastEntryAccepted = false;
    infoMixingMasternode = masternode_info_t();
    pendingDsaRequest = CPendingDsaRequest();

    CPrivateSendBaseSession::SetNull();
}

//
// Unlock coins after mixing fails or succeeds
//
void CPrivateSendClientSession::UnlockCoins()
{
    while(m_wallet_session) {
        TRY_LOCK(m_wallet_session->cs_wallet, lockWallet);
        if (!lockWallet) {MilliSleep(50); continue;}
        for (const auto& outpoint : vecOutPointLocked)
            m_wallet_session->UnlockCoin(outpoint);
        break;
    }

    vecOutPointLocked.clear();
}

std::string CPrivateSendClientSession::GetStatus(bool fWaitForBlock)
{
    static int nStatusMessageProgress = 0;
    nStatusMessageProgress += 10;
    std::string strSuffix = "";

    if (fWaitForBlock || !masternodeSync.IsBlockchainSynced())
        return strAutoDenomResult;

    switch(nState) {
        case POOL_STATE_IDLE:
            return _("PrivateSend is idle.");
        case POOL_STATE_CONNECTING:
            return strAutoDenomResult;
        case POOL_STATE_QUEUE:
            if (     nStatusMessageProgress % 70 <= 30) strSuffix = ".";
            else if (nStatusMessageProgress % 70 <= 50) strSuffix = "..";
            else if (nStatusMessageProgress % 70 <= 70) strSuffix = "...";
            return strprintf(_("Submitted to masternode, waiting in queue %s"), strSuffix);;
        case POOL_STATE_ACCEPTING_ENTRIES:
            if (nEntriesCount == 0) {
                nStatusMessageProgress = 0;
                return strAutoDenomResult;
            } else if (fLastEntryAccepted) {
                if (nStatusMessageProgress % 10 > 8) {
                    fLastEntryAccepted = false;
                    nStatusMessageProgress = 0;
                }
                return _("PrivateSend request complete:") + " " + _("Your transaction was accepted into the pool!");
            } else {
                if (     nStatusMessageProgress % 70 <= 40) return strprintf(_("Submitted following entries to masternode: %u / %d"), nEntriesCount, CPrivateSend::GetMaxPoolTransactions());
                else if (nStatusMessageProgress % 70 <= 50) strSuffix = ".";
                else if (nStatusMessageProgress % 70 <= 60) strSuffix = "..";
                else if (nStatusMessageProgress % 70 <= 70) strSuffix = "...";
                return strprintf(_("Submitted to masternode, waiting for more entries ( %u / %d ) %s"), nEntriesCount, CPrivateSend::GetMaxPoolTransactions(), strSuffix);
            }
        case POOL_STATE_SIGNING:
            if (     nStatusMessageProgress % 70 <= 40) return _("Found enough users, signing ...");
            else if (nStatusMessageProgress % 70 <= 50) strSuffix = ".";
            else if (nStatusMessageProgress % 70 <= 60) strSuffix = "..";
            else if (nStatusMessageProgress % 70 <= 70) strSuffix = "...";
            return strprintf(_("Found enough users, signing ( waiting %s )"), strSuffix);
        case POOL_STATE_ERROR:
            return _("PrivateSend request incomplete:") + " " + strLastMessage + " " + _("Will retry...");
        case POOL_STATE_SUCCESS:
            return _("PrivateSend request complete:") + " " + strLastMessage;
       default:
            return strprintf(_("Unknown state: id = %u"), nState);
    }
}

std::string CPrivateSendClientManager::GetStatuses()
{
    std::string strStatus = _("PrivateSend is idle.");

    for (auto& session : deqSessions) {
        strStatus += session.GetStatus(WaitForAnotherBlock()) + "; ";
    }
    return strStatus;
}

std::string CPrivateSendClientManager::GetSessionDenoms()
{
    std::string strSessionDenoms;

    for (auto& session : deqSessions) {
        strSessionDenoms += (session.nSessionDenom ? CPrivateSend::GetDenominationsToString(session.nSessionDenom) : "N/A") + "; ";
    }
    return strSessionDenoms.empty() ? "N/A" : strSessionDenoms;
}

bool CPrivateSendClientSession::GetMixingMasternodeInfo(masternode_info_t& mnInfoRet) const
{
    mnInfoRet = infoMixingMasternode.fInfoValid ? infoMixingMasternode : masternode_info_t();
    return infoMixingMasternode.fInfoValid;
}

bool CPrivateSendClientManager::GetMixingMasternodesInfo(std::vector<masternode_info_t>& vecMnInfoRet) const
{
    LOCK(cs_deqsessions);
    for (const auto& session : deqSessions) {
        masternode_info_t mnInfo;
        if (session.GetMixingMasternodeInfo(mnInfo)) {
            vecMnInfoRet.push_back(mnInfo);
        }
    }
    return !vecMnInfoRet.empty();
}

bool CPrivateSendClientManager::IsMixingMasternode(const CNode* pnode) const
{
    for (const auto& session : deqSessions) {
        masternode_info_t mnInfo;
        if (session.GetMixingMasternodeInfo(mnInfo)) {
            return mnInfo.fInfoValid && pnode->GetAddrLocal() == mnInfo.addr;
        }
    }
    return false;
}

//
// Check the mixing progress and send client updates if a Masternode
//
void CPrivateSendClientSession::CheckPool()
{
    // reset if we're here for 10 seconds
    if ((nState == POOL_STATE_ERROR || nState == POOL_STATE_SUCCESS) && GetTime() - nTimeLastSuccessfulStep >= 10) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CheckPool -- timeout, RESETTING\n");
        UnlockCoins();
        if (nState == POOL_STATE_ERROR) {
            keyHolderStorage.ReturnAll();
        } else {
            keyHolderStorage.KeepAll();
        }
        SetNull();
    }
}

//
// Check session timeouts
//
bool CPrivateSendClientSession::CheckTimeout()
{
    // catching hanging sessions
    switch(nState) {
        case POOL_STATE_ERROR:
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CheckTimeout -- Pool error -- Running CheckPool\n");
            CheckPool();
            break;
        case POOL_STATE_SUCCESS:
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CheckTimeout -- Pool success -- Running CheckPool\n");
            CheckPool();
            break;
        default:
            break;
    }

    int nLagTime = PRIVATESEND_QUEUE_TIMEOUT / 10; // give the server a few extra seconds before resetting.
    int nTimeout = (nState == POOL_STATE_SIGNING) ? PRIVATESEND_SIGNING_TIMEOUT : PRIVATESEND_QUEUE_TIMEOUT;
    bool fTimeout = GetTime() - nTimeLastSuccessfulStep >= nTimeout + nLagTime;

    if (nState == POOL_STATE_IDLE || !fTimeout)
        return false;

    LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CheckTimeout -- %s timed out (%ds) -- resetting\n",
             (nState == POOL_STATE_SIGNING) ? "Signing" : "Session", nTimeout);
    UnlockCoins();
    keyHolderStorage.ReturnAll();
    SetNull();
    SetState(POOL_STATE_ERROR);
    m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);

    return true;
}

//
// Check all queues and sessions for timeouts
//
void CPrivateSendClientManager::CheckTimeout()
{
    CheckQueue();

    LOCK(cs_deqsessions);
    for (auto& session : deqSessions) {
        if (session.CheckTimeout()) {
            strAutoDenomResult = _("Session timed out.");
        }
    }
}

//
// Execute a mixing denomination via a Masternode.
// This is only ran from clients
//
bool CPrivateSendClientSession::SendDenominate(const std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsIn)
{
    if (txMyCollateral == CMutableTransaction()) {
        LogPrintf("CPrivateSendClientSession:SendDenominate -- PrivateSend collateral not set\n");
        return false;
    }

    // lock the funds we're going to use
    for (const auto& txin : txMyCollateral.vin)
        vecOutPointLocked.push_back(txin.prevout);

    for (const auto& pair : vecPSInOutPairsIn)
        vecOutPointLocked.push_back(pair.first.prevout);

    // we should already be connected to a Masternode
    if (!nSessionID) {
        LogPrintf("CPrivateSendClientSession::SendDenominate -- No Masternode has been selected yet.\n");
        UnlockCoins();
        keyHolderStorage.ReturnAll();
        SetNull();
        return false;
    }

    if (!CheckDiskSpace()) {
        UnlockCoins();
        keyHolderStorage.ReturnAll();
        SetNull();
        LogPrintf("CPrivateSendClientSession::SendDenominate -- Not enough disk space, disabling PrivateSend.\n");
        return false;
    }

    SetState(POOL_STATE_ACCEPTING_ENTRIES);
    m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);
    strLastMessage = "";

    LogPrintf("CPrivateSendClientSession::SendDenominate -- Added transaction to pool.\n");

    CMutableTransaction tx; // for debug purposes only
    std::vector<CTxDSIn> vecTxDSInTmp;
    std::vector<CTxOut> vecTxOutTmp;

    for (const auto& pair : vecPSInOutPairsIn) {
        vecTxDSInTmp.emplace_back(pair.first);
        vecTxOutTmp.emplace_back(pair.second);
        tx.vin.emplace_back(pair.first);
        tx.vout.emplace_back(pair.second);
    }

    LogPrintf("CPrivateSendClientSession::SendDenominate -- Submitting partial tx %s", tx.GetHash().ToString());

    // store our entry for later use
    vecEntries.emplace_back(vecTxDSInTmp, vecTxOutTmp, CTransaction(txMyCollateral));
    RelayIn(vecEntries.back());
    nTimeLastSuccessfulStep = GetTime();

    return true;
}

// Incoming message from Masternode updating the progress of mixing
bool CPrivateSendClientSession::CheckPoolStateUpdate(PoolState nStateNew, int nEntriesCountNew, PoolStatusUpdate nStatusUpdate, PoolMessage nMessageID, int nSessionIDNew)
{
    // do not update state when mixing client state is one of these
    if (nState == POOL_STATE_IDLE || nState == POOL_STATE_ERROR || nState == POOL_STATE_SUCCESS) return false;

    strAutoDenomResult = _("Masternode:") + " " + CPrivateSend::GetMessageByID(nMessageID);

    // if rejected at any state
    if (nStatusUpdate == STATUS_REJECTED) {
        LogPrintf("CPrivateSendClientSession::CheckPoolStateUpdate -- entry is rejected by Masternode\n");
        UnlockCoins();
        keyHolderStorage.ReturnAll();
        SetNull();
        SetState(POOL_STATE_ERROR);
        m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);
        strLastMessage = CPrivateSend::GetMessageByID(nMessageID);
        return true;
    }

    if (nStatusUpdate == STATUS_ACCEPTED && nState == nStateNew) {
        if (nStateNew == POOL_STATE_QUEUE && nSessionID == 0 && nSessionIDNew != 0) {
            // new session id should be set only in POOL_STATE_QUEUE state
            nSessionID = nSessionIDNew;
            nTimeLastSuccessfulStep = GetTime();
            LogPrintf("CPrivateSendClientSession::CheckPoolStateUpdate -- set nSessionID to %d\n", nSessionID);
            return true;
        }
        else if (nStateNew == POOL_STATE_ACCEPTING_ENTRIES && nEntriesCount != nEntriesCountNew) {
            nEntriesCount = nEntriesCountNew;
            nTimeLastSuccessfulStep = GetTime();
            fLastEntryAccepted = true;
            LogPrintf("CPrivateSendClientSession::CheckPoolStateUpdate -- new entry accepted!\n");
            return true;
        }
    }

    // only situations above are allowed, fail in any other case
    return false;
}

//
// After we receive the finalized transaction from the Masternode, we must
// check it to make sure it's what we want, then sign it if we agree.
// If we refuse to sign, it's possible we'll be charged collateral
//
bool CPrivateSendClientSession::SignFinalTransaction(const CTransaction& finalTransactionNew, CNode* pnode)
{
    if (pnode == nullptr || !m_wallet_session) return false;

    CMutableTransaction tx {finalTransactionNew};
    finalMutableTransaction = tx;
    LogPrintf("CPrivateSendClientSession::SignFinalTransaction -- finalMutableTransaction=%s\n", finalMutableTransaction.GetHash().ToString());

    std::vector<CTxIn> sigs;

    //make sure my inputs/outputs are present, otherwise refuse to sign
    for (const auto& entry : vecEntries) {
        for (const auto& txdsin : entry.vecTxDSIn) {
            /* Sign my transaction and all outputs */
            int nMyInputIndex = -1;
            CScript prevPubKey = CScript();
            CTxIn txin = CTxIn();

            for(unsigned int i = 0; i < finalMutableTransaction.vin.size(); i++) {
                if (finalMutableTransaction.vin[i] == txdsin) {
                    nMyInputIndex = i;
                    prevPubKey = txdsin.prevPubKey;
                    txin = txdsin;
                }
            }

            if (nMyInputIndex >= 0) { //might have to do this one input at a time?
                int nFoundOutputsCount = 0;
                CAmount nValue1 = 0;
                CAmount nValue2 = 0;

                for (const auto& txoutFinal : finalMutableTransaction.vout) {
                    for (const auto& txout: entry.vecTxOut) {
                        if (txoutFinal == txout) {
                            nFoundOutputsCount++;
                            nValue1 += txoutFinal.nValue;
                        }
                    }
                }

                for (const auto& txout : entry.vecTxOut)
                    nValue2 += txout.nValue;

                int nTargetOuputsCount = entry.vecTxOut.size();
                if (nFoundOutputsCount < nTargetOuputsCount || nValue1 != nValue2) {
                    // in this case, something went wrong and we'll refuse to sign. It's possible we'll be charged collateral. But that's
                    // better then signing if the transaction doesn't look like what we wanted.
                    LogPrintf("CPrivateSendClientSession::SignFinalTransaction -- My entries are not correct! Refusing to sign: nFoundOutputsCount: %d, nTargetOuputsCount: %d\n", nFoundOutputsCount, nTargetOuputsCount);
                    UnlockCoins();
                    keyHolderStorage.ReturnAll();
                    SetNull();

                    return false;
                }

                LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::SignFinalTransaction -- Signing my input %i\n", nMyInputIndex);
                if (!SignSignature(*m_wallet_session, prevPubKey, finalMutableTransaction, nMyInputIndex, nValue2, int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))) { // changes scriptSig
                    LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::SignFinalTransaction -- Unable to sign my own transaction!\n");
                    // not sure what to do here, it will timeout...?
                }

                sigs.push_back(finalMutableTransaction.vin[nMyInputIndex]);
                LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::SignFinalTransaction -- nMyInputIndex: %d, sigs.size(): %d, scriptSig=%s\n", nMyInputIndex, (int)sigs.size(), ScriptToAsmStr(finalMutableTransaction.vin[nMyInputIndex].scriptSig));
            }
        }
    }

    if (sigs.empty()) {
        LogPrintf("CPrivateSendClientSession::SignFinalTransaction -- can't sign anything!\n");
        UnlockCoins();
        keyHolderStorage.ReturnAll();
        SetNull();

        return false;
    }

    // push all of our signatures to the Masternode
    LogPrintf("CPrivateSendClientSession::SignFinalTransaction -- pushing sigs to the masternode, finalMutableTransaction=%s\n", finalMutableTransaction.GetHash().ToString());
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    g_connman.get()->PushMessage(pnode, msgMaker.Make(NetMsgType::DSSIGNFINALTX, sigs));
    SetState(POOL_STATE_SIGNING);
    m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);
    nTimeLastSuccessfulStep = GetTime();

    return true;
}

// mixing transaction was completed (failed or successful)
void CPrivateSendClientSession::CompletedTransaction(PoolMessage nMessageID)
{
    if (nMessageID == MSG_SUCCESS) {
        LogPrintf("CompletedTransaction -- success\n");
        m_wallet_session->privateSendClient->UpdatedSuccessBlock();
        keyHolderStorage.KeepAll();
    } else {
        LogPrintf("CompletedTransaction -- error\n");
        keyHolderStorage.ReturnAll();
    }
    UnlockCoins();
    SetNull();
    strLastMessage = CPrivateSend::GetMessageByID(nMessageID);
}

void CPrivateSendClientManager::UpdatedSuccessBlock()
{
    nCachedLastSuccessBlock = nCachedBlockHeight;
}

bool CPrivateSendClientManager::IsDenomSkipped(const CAmount& nDenomValue)
{
    return std::find(vecDenominationsSkipped.begin(), vecDenominationsSkipped.end(), nDenomValue) != vecDenominationsSkipped.end();
}

void CPrivateSendClientManager::AddSkippedDenom(const CAmount& nDenomValue)
{
    vecDenominationsSkipped.push_back(nDenomValue);
}

bool CPrivateSendClientManager::WaitForAnotherBlock()
{
    if (!masternodeSync.IsMasternodeListSynced())
        return true;

    if (fPrivateSendMultiSession)
        return false;

    return nCachedBlockHeight - nCachedLastSuccessBlock < nMinBlocksToWait;
}

bool CPrivateSendClientManager::CheckAutomaticBackup()
{
    if (!m_wallet) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- Wallet is not initialized, no mixing available.\n");
        strAutoDenomResult = _("Wallet is not initialized") + ", " + _("no mixing available.");
        fEnablePrivateSend = false; // no mixing
        return false;
    }

    switch(nWalletBackups) {
        case 0:
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- Automatic backups disabled, no mixing available.\n");
            strAutoDenomResult = _("Automatic backups disabled") + ", " + _("no mixing available.");
            fEnablePrivateSend = false; // stop mixing
            m_wallet->nKeysLeftSinceAutoBackup = 0; // no backup, no "keys since last backup"
            return false;
        case -1:
            // Automatic backup failed, nothing else we can do until user fixes the issue manually.
            // There is no way to bring user attention in daemon mode so we just update status and
            // keep spamming if debug is on.
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- ERROR! Failed to create automatic backup.\n");
            strAutoDenomResult = _("ERROR! Failed to create automatic backup") + ", " + _("see debug.log for details.");
            return false;
        case -2:
            // We were able to create automatic backup but keypool was not replenished because wallet is locked.
            // There is no way to bring user attention in daemon mode so we just update status and
            // keep spamming if debug is on.
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- WARNING! Failed to create replenish keypool, please unlock your wallet to do so.\n");
            strAutoDenomResult = _("WARNING! Failed to replenish keypool, please unlock your wallet to do so.") + ", " + _("see debug.log for details.");
            return false;
    }

    if (m_wallet->nKeysLeftSinceAutoBackup < PRIVATESEND_KEYS_THRESHOLD_STOP) {
        // We should never get here via mixing itself but probably smth else is still actively using keypool
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- Very low number of keys left: %d, no mixing available.\n", m_wallet->nKeysLeftSinceAutoBackup);
        strAutoDenomResult = strprintf(_("Very low number of keys left: %d") + ", " + _("no mixing available."), m_wallet->nKeysLeftSinceAutoBackup);
        // It's getting really dangerous, stop mixing
        fEnablePrivateSend = false;
        return false;
    } else if (m_wallet->nKeysLeftSinceAutoBackup < PRIVATESEND_KEYS_THRESHOLD_WARNING) {
        // Low number of keys left but it's still more or less safe to continue
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- Very low number of keys left: %d\n", m_wallet->nKeysLeftSinceAutoBackup);
        strAutoDenomResult = strprintf(_("Very low number of keys left: %d"), m_wallet->nKeysLeftSinceAutoBackup);

        if (fCreateAutoBackups) {
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- Trying to create new backup.\n");
            std::string warningString;
            std::string errorString;
            std::shared_ptr<CWallet> const pwallet = GetWallet(m_wallet->GetName());

            if (!AutoBackupWallet(pwallet, WalletLocation(), warningString, errorString)) {
                if (!warningString.empty()) {
                    // There were some issues saving backup but yet more or less safe to continue
                    LogPrintf("CPrivateSendClientManager::CheckAutomaticBackup -- WARNING! Something went wrong on automatic backup: %s\n", warningString);
                }
                if (!errorString.empty()) {
                    // Things are really broken
                    LogPrintf("CPrivateSendClientManager::CheckAutomaticBackup -- ERROR! Failed to create automatic backup: %s\n", errorString);
                    strAutoDenomResult = strprintf(_("ERROR! Failed to create automatic backup") + ": %s", errorString);
                    return false;
                }
            }
        } else {
            // Wait for smth else (e.g. GUI action) to create automatic backup for us
            return false;
        }
    }

    LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::CheckAutomaticBackup -- Keys left since latest backup: %d\n", m_wallet->nKeysLeftSinceAutoBackup);

    return true;
}

//
// Passively run mixing in the background to anonymize funds based on the given configuration.
//
void CPrivateSendClientSession::DoAutomaticDenominating()
{
    if (nState != POOL_STATE_IDLE) return;

    if (!masternodeSync.IsMasternodeListSynced()) {
        strAutoDenomResult = _("Waiting for sync to finish...");
        return;
    }

    if (!m_wallet_session) {
        strAutoDenomResult = _("Wallet is not initialized, load wallet, will retry...");
        return;
    }

    CAmount nBalanceNeedsAnonymized;
    CAmount nValueMin = CPrivateSend::GetSmallestDenomination();

    {
        auto locked_chain = m_wallet_session->chain().lock();
        LOCK(m_wallet_session->cs_wallet);

        if (m_wallet_session->IsLocked(true)) {
            strAutoDenomResult = _("Wallet is locked, will retry...");
            return;
        }

        if (GetEntriesCount() > 0) {
            strAutoDenomResult = _("Mixing in progress...");
            return;
        }

        TRY_LOCK(cs_privatesend, lockDS);
        if (!lockDS) {
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::DoAutomaticDenominating -- mutex locked, returning\n");
            strAutoDenomResult = _("Client busy...");
            return;
        }

        if (mnodeman.size() == 0) {
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::DoAutomaticDenominating -- No Masternodes detected\n");
            strAutoDenomResult = _("No Masternodes detected, will retry...");
            return;
        }

        // if there are no confirmed DS collateral inputs yet
        if (!m_wallet_session->HasCollateralInputs()) {
            // should have some additional amount for them
            nValueMin += CPrivateSend::GetMaxCollateralAmount();
        }

        // including denoms but applying some restrictions
        nBalanceNeedsAnonymized = m_wallet_session->GetNeedsToBeAnonymizedBalance(nValueMin);

        // anonymizable balance is way too small
        if (nBalanceNeedsAnonymized < nValueMin) {
            LogPrintf("CPrivateSendClientSession::DoAutomaticDenominating -- Not enough funds to anonymize\n");
            strAutoDenomResult = _("Not enough funds to anonymize, will retry...");
            return;
        }

        // excluding denoms
        CAmount nBalanceAnonimizableNonDenom = m_wallet_session->GetAnonymizableBalance(true);
        // denoms
        CAmount nBalanceDenominated = m_wallet_session->GetDenominatedBalance();

        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::DoAutomaticDenominating -- nValueMin: %f, nBalanceNeedsAnonymized: %f, nBalanceAnonimizableNonDenom: %f, nBalanceDenominated: %f\n",
            (float)nValueMin / COIN,
            (float)nBalanceNeedsAnonymized / COIN,
            (float)nBalanceAnonimizableNonDenom / COIN,
            (float)nBalanceDenominated / COIN);

        // Check if we have should create more denominated inputs i.e.
        // there are funds to denominate and denominated balance does not exceed
        // max amount to mix yet.
        if (nBalanceAnonimizableNonDenom >= nValueMin + CPrivateSend::GetCollateralAmount() && nBalanceDenominated < m_wallet_session->privateSendClient->nPrivateSendAmount * COIN) {
            strAutoDenomResult = _("Creating denominated outputs.");
            CreateDenominated();
            return;
        }

        //check if we have the collateral sized inputs
        if (!m_wallet_session->HasCollateralInputs())
            if (!MakeCollateralAmounts()) return;

        if (nSessionID) {
            strAutoDenomResult = _("Mixing in progress...");
            return;
        }

        // Initial phase, find a Masternode
        // Clean if there is anything left from previous session
        UnlockCoins();
        keyHolderStorage.ReturnAll();
        SetNull();

        //check our collateral and create new if needed
        std::string strReason;
        bool fOK = true;
        if (txMyCollateral == CMutableTransaction()) {
            if (!m_wallet_session->CreateCollateralTransaction(txMyCollateral, strReason)) {
                fOK = false;
            }
        } else {
            if (!CPrivateSend::IsCollateralValid(CTransaction(txMyCollateral))) {
                LogPrintf("CPrivateSendClientSession::DoAutomaticDenominating -- invalid collateral, recreating...\n");
                if (!m_wallet_session->CreateCollateralTransaction(txMyCollateral, strReason)) {
                    fOK = false;
                }
            }
        }

        if (!fOK) {
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::DoAutomaticDenominating -- create collateral error: %s\n", strReason);
            strAutoDenomResult = _("Can not create collateral, enough funds? Will retry...");
            return;
        }
    } // LOCK(m_wallet_session->cs_wallet);

    // don't use the queues all of the time for mixing unless we are a liquidity provider
    if ((m_wallet_session->privateSendClient->nLiquidityProvider || GetRandInt(100) > 33) && JoinExistingQueue(nBalanceNeedsAnonymized)) return;

    // do not initiate queue if we are a liquidity provider to avoid useless inter-mixing
    if (m_wallet_session->privateSendClient->nLiquidityProvider) return;

    // initiate new queue, result is updated in sub-routine
    if (StartNewQueue(nValueMin, nBalanceNeedsAnonymized)) return;

    // network is not ready, try later
    strAutoDenomResult = _("No compatible Masternode found, will retry...");
    return;
}

void CPrivateSendClientManager::DoAutomaticDenominating()
{
    if (WaitForAnotherBlock()) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::DoAutomaticDenominating -- Last successful PrivateSend action was too recent\n");
        if (!masternodeSync.IsMasternodeListSynced()) {
            strAutoDenomResult = _("Waiting for sync to finish...");
        } else {
            strAutoDenomResult = _("Waiting for more blocks...");
            return;
        }
    }

    if (!m_wallet) {
        strAutoDenomResult = _("Wallet is not initialized.");
        return;
    }

    if (m_wallet->IsLocked(true)) {
        strAutoDenomResult = _("Wallet is locked.");
        return;
    }

    int nMnCountEnabled = mnodeman.CountEnabled(MIN_PRIVATESEND_PEER_PROTO_VERSION);

    // If we've used 90% of the Masternode list then drop the oldest first ~30%
    int nThreshold_high = nMnCountEnabled * 0.9;
    int nThreshold_low = nThreshold_high * 0.7;
    LogPrint(BCLog::PRIVSEND, "Checking vecMasternodesUsed: size: %d, threshold: %d\n", (int)vecMasternodesUsed.size(), nThreshold_high);

    if ((int)vecMasternodesUsed.size() > nThreshold_high) {
        vecMasternodesUsed.erase(vecMasternodesUsed.begin(), vecMasternodesUsed.begin() + vecMasternodesUsed.size() - nThreshold_low);
        LogPrint(BCLog::PRIVSEND, "  vecMasternodesUsed: new size: %d, threshold: %d\n", (int)vecMasternodesUsed.size(), nThreshold_high);
    }

    LOCK(cs_deqsessions);
    if ((int)deqSessions.size() < nPrivateSendSessions) {
        deqSessions.emplace_back(m_wallet);
    }
    for (auto& session : deqSessions) {
        if (!CheckAutomaticBackup()) {
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientManager::DoAutomaticDenominating -- Failed to create automatic backup\n");
            strAutoDenomResult = _("Failed to create automatic backup.");
            fEnablePrivateSend = false;
            return;
        }
        session.DoAutomaticDenominating();
    }
}

void CPrivateSendClientManager::AddUsedMasternode(const COutPoint& outpointMn)
{
    vecMasternodesUsed.push_back(outpointMn);
}

masternode_info_t CPrivateSendClientManager::GetNotUsedMasternode()
{
    return mnodeman.FindRandomNotInVec(vecMasternodesUsed, MIN_PRIVATESEND_PEER_PROTO_VERSION);
}

bool CPrivateSendClientSession::JoinExistingQueue(CAmount nBalanceNeedsAnonymized)
{
    if (!m_wallet_session) return false;

    std::vector<CAmount> vecStandardDenoms = CPrivateSend::GetStandardDenominations();
    // Look through the queues and see if anything matches
    CPrivateSendQueue dsq;
    while (m_wallet_session->privateSendClient->GetQueueItemAndTry(dsq)) {
        masternode_info_t infoMn;

        if (!mnodeman.GetMasternodeInfo(dsq.masternodeOutpoint, infoMn)) {
            LogPrintf("CPrivateSendClientSession::JoinExistingQueue -- dsq masternode is not in masternode list, masternode=%s\n", dsq.masternodeOutpoint.ToStringShort());
            continue;
        }

        if (infoMn.nProtocolVersion < MIN_PRIVATESEND_PEER_PROTO_VERSION) continue;

        std::vector<int> vecBits;
        if (!CPrivateSend::GetDenominationsBits(dsq.nDenom, vecBits)) {
            // incompatible denom
            continue;
        }

        // mixing rate limit i.e. nLastDsq check should already pass in DSQUEUE ProcessMessage
        // in order for dsq to get into vecPrivateSendQueue, so we should be safe to mix already,
        // no need for additional verification here

        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::JoinExistingQueue -- found valid queue: %s\n", dsq.ToString());

        std::vector<std::pair<CTxDSIn, CTxOut> > vecPSInOutPairsTmp;
        CAmount nMinAmount = vecStandardDenoms[vecBits.front()];
        CAmount nMaxAmount = nBalanceNeedsAnonymized;

        // Try to match their denominations if possible, select exact number of denominations
        if (!m_wallet_session->SelectPSInOutPairsByDenominations(dsq.nDenom, nMinAmount, nMaxAmount, vecPSInOutPairsTmp)) {
            LogPrintf("CPrivateSendClientSession::JoinExistingQueue -- Couldn't match %d denominations %d (%s)\n", vecBits.front(), dsq.nDenom, CPrivateSend::GetDenominationsToString(dsq.nDenom));
            continue;
        }

        m_wallet_session->privateSendClient->AddUsedMasternode(dsq.masternodeOutpoint);

        if (g_connman.get()->IsDisconnectRequested(infoMn.addr)) {
            LogPrintf("CPrivateSendClientSession::JoinExistingQueue -- skipping connection, addr=%s\n", infoMn.addr.ToString());
            continue;
        }

        nSessionDenom = dsq.nDenom;
        infoMixingMasternode = infoMn;
        pendingDsaRequest = CPendingDsaRequest(infoMn.addr, CPrivateSendAccept(nSessionDenom, txMyCollateral));
        g_connman.get()->AddPendingMasternode(infoMn.addr);
        SetState(POOL_STATE_CONNECTING);
        m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);
        nTimeLastSuccessfulStep = GetTime();
        LogPrintf("CPrivateSendClientSession::JoinExistingQueue -- pending connection (from queue): nSessionDenom: %d (%s), addr=%s\n",
            nSessionDenom, CPrivateSend::GetDenominationsToString(nSessionDenom), infoMn.addr.ToString());
        strAutoDenomResult = _("Trying to connect...");
        return true;
    }
    strAutoDenomResult = _("Failed to find mixing queue to join, will retry...");
    return false;
}

bool CPrivateSendClientSession::StartNewQueue(CAmount nValueMin, CAmount nBalanceNeedsAnonymized)
{
    if (!m_wallet_session) return false;

    int nTries = 0;
    int nMnCountEnabled = mnodeman.CountEnabled(MIN_PRIVATESEND_PEER_PROTO_VERSION);

    // ** find the coins we'll use
    std::vector<CTxIn> vecTxIn;
    CAmount nValueInTmp = 0;
    if (!m_wallet_session->SelectPrivateCoins(nValueMin, nBalanceNeedsAnonymized, vecTxIn, nValueInTmp, 0, m_wallet_session->privateSendClient->nPrivateSendRounds)) {
        // this should never happen
        LogPrintf("CPrivateSendClientSession::StartNewQueue -- Can't mix: no compatible inputs found!\n");
        strAutoDenomResult = _("Can't mix: no compatible inputs found!");
        return false;
    }

    // otherwise, try one randomly
    while(nTries < 30) {
        masternode_info_t infoMn = m_wallet_session->privateSendClient->GetNotUsedMasternode();

        if (!infoMn.fInfoValid) {
            LogPrintf("CPrivateSendClientSession::StartNewQueue -- Can't find random masternode!\n");
            strAutoDenomResult = _("Can't find random Masternode, will retry...");
            return false;
        }

        m_wallet_session->privateSendClient->AddUsedMasternode(infoMn.outpoint);

        // skip next mn payments winners
        if (mnpayments.IsScheduled(infoMn, 0)) {
            LogPrintf("CPrivateSendClientSession::StartNewQueue -- skipping winner, masternode=%s\n", infoMn.outpoint.ToStringShort());
            nTries++;
            continue;
        }

        if (infoMn.nLastDsq != 0 && infoMn.nLastDsq + nMnCountEnabled/5 > mnodeman.nDsqCount) {
            LogPrintf("CPrivateSendClientSession::StartNewQueue -- Too early to mix on this masternode!" /* Continued */
                        " masternode=%s  addr=%s  nLastDsq=%d  CountEnabled/5=%d  nDsqCount=%d\n",
                        infoMn.outpoint.ToStringShort(), infoMn.addr.ToString(), infoMn.nLastDsq,
                        nMnCountEnabled/5, mnodeman.nDsqCount);
            nTries++;
            continue;
        }

        // this should never happen
        if (g_connman.get()->IsDisconnectRequested(infoMn.addr)) {
            LogPrintf("CPrivateSendClientSession::StartNewQueue -- skipping connection, addr=%s\n", infoMn.addr.ToString());
            continue;
        }

        LogPrintf("CPrivateSendClientSession::StartNewQueue -- attempt %d connection to Masternode %s\n", nTries, infoMn.addr.ToString());

        std::vector<CAmount> vecAmounts;
        m_wallet_session->ConvertList(vecTxIn, vecAmounts);
        // try to get a single random denom out of vecAmounts
        while(nSessionDenom == 0) {
            nSessionDenom = CPrivateSend::GetDenominationsByAmounts(vecAmounts);
        }

        infoMixingMasternode = infoMn;
        g_connman.get()->AddPendingMasternode(infoMn.addr);
        pendingDsaRequest = CPendingDsaRequest(infoMn.addr, CPrivateSendAccept(nSessionDenom, txMyCollateral));
        SetState(POOL_STATE_CONNECTING);
        m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);
        nTimeLastSuccessfulStep = GetTime();
        LogPrintf("CPrivateSendClientSession::StartNewQueue -- pending connection, nSessionDenom: %d (%s), addr=%s\n",
            nSessionDenom, CPrivateSend::GetDenominationsToString(nSessionDenom), infoMn.addr.ToString());
        strAutoDenomResult = _("Trying to connect...");
        return true;
    }
    strAutoDenomResult = _("Failed to start a new mixing queue, will retry...");
    return false;
}

bool CPrivateSendClientSession::ProcessPendingDsaRequest(CConnman* connman)
{
    if (!pendingDsaRequest) return false;

    bool fDone = connman->ForNode(pendingDsaRequest.GetAddr(), [&](CNode* pnode) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::%s -- processing dsa queue for addr=%s\n", __func__, pnode->GetAddrLocal().ToString());
        nTimeLastSuccessfulStep = GetTime();
        SetState(POOL_STATE_QUEUE);
        m_wallet_session->NotifyTransactionChanged(m_wallet_session, txMyCollateral.GetHash(), CT_UPDATED);
        CNetMsgMaker msgMaker(pnode->GetSendVersion());
        connman->PushMessage(pnode, msgMaker.Make(NetMsgType::DSACCEPT, pendingDsaRequest.GetDSA()));
        return true;
    });

    if (fDone) {
        pendingDsaRequest = CPendingDsaRequest();
    } else if (pendingDsaRequest.IsExpired()) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::%s -- failed to connect to %s\n", __func__, pendingDsaRequest.GetAddr().ToString());
        SetNull();
    }

    return fDone;
}

void CPrivateSendClientManager::ProcessPendingDsaRequest()
{
    LOCK(cs_deqsessions);
    for (auto& session : deqSessions) {
        if (session.ProcessPendingDsaRequest(g_connman.get())) {
            strAutoDenomResult = _("Mixing in progress...");
        }
    }
}

bool CPrivateSendClientSession::SubmitDenominate()
{
    LOCK(m_wallet_session->cs_wallet);

    std::string strError;
    std::vector<std::pair<CTxDSIn, CTxOut> > vecPSInOutPairs, vecPSInOutPairsTmp;

    if (!SelectDenominate(strError, vecPSInOutPairs)) {
        LogPrintf("CPrivateSendClientSession::SubmitDenominate -- SelectDenominate failed, error: %s\n", strError);
        return false;
    }

    std::vector<std::pair<int, size_t> > vecInputsByRounds;
    // Note: liquidity providers are fine with whatever number of inputs they've got
    bool fDryRun = m_wallet_session->privateSendClient->nLiquidityProvider == 0;

    for (int i = 0; i < m_wallet_session->privateSendClient->nPrivateSendRounds; i++) {
        if (PrepareDenominate(i, i, strError, vecPSInOutPairs, vecPSInOutPairsTmp)) {
            LogPrintf("CPrivateSendClientSession::SubmitDenominate -- Running PrivateSend denominate for %d rounds, success\n", i);
            if (!fDryRun) {
                return SendDenominate(vecPSInOutPairsTmp);
            }
            vecInputsByRounds.emplace_back(i, vecPSInOutPairsTmp.size());
        } else {
            LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::SubmitDenominate -- Running PrivateSend denominate for %d rounds, error: %s\n", i, strError);
        }
    }

    /*
    // more inputs first, for equal input count prefer the one with less rounds
    std::sort(vecInputsByRounds.begin(), vecInputsByRounds.end(), [](const auto& a, const auto& b) {
        return a.second > b.second || (a.second == b.second && a.first < b.first);
    });
    */
    LogPrint(BCLog::PRIVSEND, "vecInputsByRounds for denom %d\n", nSessionDenom);
    for (const auto& pair : vecInputsByRounds) {
        LogPrint(BCLog::PRIVSEND, "vecInputsByRounds: rounds: %d, inputs: %d\n", pair.first, pair.second);
    }

    int nRounds = vecInputsByRounds.begin()->first;
    if (PrepareDenominate(nRounds, nRounds, strError, vecPSInOutPairs, vecPSInOutPairsTmp)) {
        LogPrintf("CPrivateSendClientSession::SubmitDenominate -- Running PrivateSend denominate for %d rounds, success\n", nRounds);
        return SendDenominate(vecPSInOutPairsTmp);
    }

    // We failed? That's strange but let's just make final attempt and try to mix everything
    if (PrepareDenominate(0, m_wallet_session->privateSendClient->nPrivateSendRounds - 1, strError, vecPSInOutPairs, vecPSInOutPairsTmp)) {
        LogPrintf("CPrivateSendClientSession::SubmitDenominate -- Running PrivateSend denominate for all rounds, success\n");
        return SendDenominate(vecPSInOutPairsTmp);
    }

    // Should never actually get here but just in case
    LogPrintf("CPrivateSendClientSession::SubmitDenominate -- Running PrivateSend denominate for all rounds, error: %s\n", strError);
    strAutoDenomResult = strError;
    return false;
}

bool CPrivateSendClientSession::SelectDenominate(std::string& strErrorRet, std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsRet)
{
    if (!m_wallet_session) {
        strErrorRet = "Wallet is not initialized";
        return false;
    }

    if (m_wallet_session->IsLocked(true)) {
        strErrorRet = "Wallet locked, unable to create transaction!";
        return false;
    }

    if (GetEntriesCount() > 0) {
        strErrorRet = "Already have pending entries in the PrivateSend pool";
        return false;
    }

    vecPSInOutPairsRet.clear();

    std::vector<int> vecBits;
    if (!CPrivateSend::GetDenominationsBits(nSessionDenom, vecBits)) {
        strErrorRet = "Incorrect session denom";
        return false;
    }
    std::vector<CAmount> vecStandardDenoms = CPrivateSend::GetStandardDenominations();

    bool fSelected = m_wallet_session->SelectPSInOutPairsByDenominations(nSessionDenom, vecStandardDenoms[vecBits.front()], CPrivateSend::GetMaxPoolAmount(), vecPSInOutPairsRet);
    if (!fSelected) {
        strErrorRet = "Can't select current denominated inputs";
        return false;
    }

    return true;
}

bool CPrivateSendClientSession::PrepareDenominate(int nMinRounds, int nMaxRounds, std::string& strErrorRet, const std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsIn, std::vector<std::pair<CTxDSIn, CTxOut> >& vecPSInOutPairsRet)
{
    std::vector<int> vecBits;
    if (!CPrivateSend::GetDenominationsBits(nSessionDenom, vecBits)) {
        strErrorRet = "Incorrect session denom";
        return false;
    }

    LOCK(m_wallet_session->cs_wallet);

    for (const auto& pair : vecPSInOutPairsIn) {
        m_wallet_session->LockCoin(pair.first.prevout);
    }

    // NOTE: No need to randomize order of inputs because they were
    // initially shuffled in CWallet::SelectPSInOutPairsByDenominations already.
    int nDenomResult{0};

    std::vector<CAmount> vecStandardDenoms = CPrivateSend::GetStandardDenominations();
    std::vector<int> vecSteps(vecStandardDenoms.size(), 0);
    vecPSInOutPairsRet.clear();

    // Try to add up to PRIVATESEND_ENTRY_MAX_SIZE of every needed denomination
    for (const auto& pair : vecPSInOutPairsIn) {
        if (pair.second.nRounds < nMinRounds || pair.second.nRounds > nMaxRounds) {
            // unlock unused coins
            m_wallet_session->UnlockCoin(pair.first.prevout);
            continue;
        }
        bool fFound = false;
        for (const auto& nBit : vecBits) {
            if ((size_t)vecSteps[nBit] >= PRIVATESEND_ENTRY_MAX_SIZE) break;
            CAmount nValueDenom = vecStandardDenoms[nBit];
            if (pair.second.nValue == nValueDenom) {
                // randomly skip some inputs when we have at least one of the same denom already
                // TODO: make it adjustable via options/cmd-line params
                if (vecSteps[nBit] >= 1 && GetRandInt(5) == 0) {
                    // still count it as a step to randomize number of inputs
                    // if we have more than (or exactly) PRIVATESEND_ENTRY_MAX_SIZE of them
                    ++vecSteps[nBit];
                    break;
                }
                std::shared_ptr<CReserveScript> scriptDenom;
                keyHolderStorage.AddKey(scriptDenom, m_wallet_session);
                vecPSInOutPairsRet.emplace_back(pair.first, CTxOut(nValueDenom, scriptDenom->reserveScript));
                fFound = true;
                nDenomResult |= 1 << nBit;
                // step is complete
                ++vecSteps[nBit];
                break;
            }
        }
        if (!fFound) {
            // unlock unused coins and if we are not going to mix right away
            m_wallet_session->UnlockCoin(pair.first.prevout);
        }
    }

    if (nDenomResult != nSessionDenom) {
        // unlock used coins on failure
        for (const auto& pair : vecPSInOutPairsRet) {
            m_wallet_session->UnlockCoin(pair.first.prevout);
        }
        keyHolderStorage.ReturnAll();
        strErrorRet = "Can't prepare current denominated outputs";
        return false;
    }

    return true;
}

// Create collaterals by looping through inputs grouped by addresses
bool CPrivateSendClientSession::MakeCollateralAmounts()
{
    if (!m_wallet_session) return false;

    std::vector<CompactTallyItem> vecTally;
    if (!m_wallet_session->SelectCoinsGroupedByAddresses(vecTally, false)) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::MakeCollateralAmounts -- SelectCoinsGroupedByAddresses can't find any inputs!\n");
        strAutoDenomResult = _("Can not find any inputs, enough funds? Will retry...");
        return false;
    }

    // Start from smallest balances first to consume tiny amounts and cleanup UTXO a bit
    std::sort(vecTally.begin(), vecTally.end(), [](const CompactTallyItem& a, const CompactTallyItem& b) {
        return a.nAmount < b.nAmount;
    });

    // First try to use only non-denominated funds
    for (const auto& item : vecTally) {
        if (!MakeCollateralAmounts(item, false)) continue;
        strAutoDenomResult = _("Prepared collateral...");
        return true;
    }

    // There should be at least some denominated funds we should be able to break in pieces to continue mixing
    for (const auto& item : vecTally) {
        if (!MakeCollateralAmounts(item, true)) continue;
        strAutoDenomResult = _("Prepared collateral...");
        return true;
    }

    // If we got here then smth is terribly broken actually
    LogPrintf("CPrivateSendClientSession::MakeCollateralAmounts -- ERROR: Can't make collaterals!\n");
    strAutoDenomResult = _("ERROR: Can not make collaterals. Will retry...");
    return false;
}

// Split up large inputs or create fee sized inputs
bool CPrivateSendClientSession::MakeCollateralAmounts(const CompactTallyItem& tallyItem, bool fTryDenominated)
{
    if (!m_wallet_session) return false;

    LOCK(m_wallet_session->cs_wallet);

    // denominated input is always a single one, so we can check its amount directly and return early
    if (!fTryDenominated && tallyItem.vecOutPoints.size() == 1 && CPrivateSend::IsDenominatedAmount(tallyItem.nAmount)) {
        return false;
    }

    CTransactionRef tx;
    CWalletTx wtx(m_wallet_session, tx);
    CAmount nFeeRet = 0;
    int nChangePosRet = -1;
    std::string strFail = "";
    std::vector<CRecipient> vecSend;

    // make our collateral address
    CReserveKey reservekeyCollateral(m_wallet_session);
    // make our change address
    CReserveKey reservekeyChange(m_wallet_session);

    CScript scriptCollateral;
    CPubKey vchPubKey;
    assert(reservekeyCollateral.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
    scriptCollateral = GetScriptForDestination(vchPubKey.GetID());

    vecSend.push_back((CRecipient){scriptCollateral, CPrivateSend::GetMaxCollateralAmount(), false});

    // try to use non-denominated and not mn-like funds first, select them explicitly
    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    // send change to the same address so that we were able create more denoms out of it later
    coinControl.destChange = tallyItem.txdest;
    for (const auto& outpoint : tallyItem.vecOutPoints)
        coinControl.Select(outpoint);

    auto locked_chain = m_wallet_session->chain().lock();

    bool fSuccess = m_wallet_session->CreateTransaction(*locked_chain, vecSend, tx, reservekeyChange,
            nFeeRet, nChangePosRet, strFail, coinControl, true, ONLY_NONDENOMINATED);
    if (!fSuccess) {
        LogPrintf("CPrivateSendClientSession::MakeCollateralAmounts -- ONLY_NONDENOMINATED: %s\n", strFail);
        // If we failed then most likely there are not enough funds on this address.
        if (fTryDenominated) {
            // Try to also use denominated coins (we can't mix denominated without collaterals anyway).
            if (!m_wallet_session->CreateTransaction(*locked_chain, vecSend, tx, reservekeyChange,
                                nFeeRet, nChangePosRet, strFail, coinControl, true, ALL_COINS)) {
                LogPrintf("CPrivateSendClientSession::MakeCollateralAmounts -- ALL_COINS Error: %s\n", strFail);
                reservekeyCollateral.ReturnKey();
                return false;
            }
        } else {
            // Nothing else we can do.
            reservekeyCollateral.ReturnKey();
            return false;
        }
    }

    reservekeyCollateral.KeepKey();

    LogPrintf("CPrivateSendClientSession::MakeCollateralAmounts -- txid=%s\n", wtx.GetHash().GetHex());

    // use the same nCachedLastSuccessBlock as for DS mixing to prevent race
    CValidationState state;
    if (!m_wallet_session->CommitTransaction(MakeTransactionRef(std::move(*wtx.tx)), std::move(wtx.mapValue), {} /* orderForm */, reservekeyChange, g_connman.get(), state)) {
        LogPrintf("CPrivateSendClientSession::MakeCollateralAmounts -- CommitTransaction failed! Reason given: %s\n", state.GetRejectReason());
        return false;
    }

    m_wallet_session->privateSendClient->UpdatedSuccessBlock();

    return true;
}

// Create denominations by looping through inputs grouped by addresses
bool CPrivateSendClientSession::CreateDenominated()
{
    if (!m_wallet_session) return false;

    LOCK(m_wallet_session->cs_wallet);

    // NOTE: We do not allow txes larger than 100kB, so we have to limit number of inputs here.
    // We still want to consume a lot of inputs to avoid creating only smaller denoms though.
    // Knowing that each CTxIn is at least 148b big, 400 inputs should take 400 x ~148b = ~60kB.
    // This still leaves more than enough room for another data of typical CreateDenominated tx.
    std::vector<CompactTallyItem> vecTally;
    if (!m_wallet_session->SelectCoinsGroupedByAddresses(vecTally, true, true, 400)) {
        LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CreateDenominated -- SelectCoinsGroupedByAddresses can't find any inputs!\n");
        strAutoDenomResult = _("Can not select any inputs, enough funds? Will retry...");
        return false;
    }

    // Start from largest balances first to speed things up by creating txes with larger/largest denoms included
    std::sort(vecTally.begin(), vecTally.end(), [](const CompactTallyItem& a, const CompactTallyItem& b) {
        return a.nAmount > b.nAmount;
    });

    bool fCreateMixingCollaterals = !m_wallet_session->HasCollateralInputs();

    for (const auto& item : vecTally) {
        if (!CreateDenominated(item, fCreateMixingCollaterals)) continue;
        return true;
    }

    LogPrintf("CPrivateSendClientSession::CreateDenominated -- failed!\n");
    strAutoDenomResult = _("Can not create transaction, keypool exhausted? Will retry...");
    return false;
}

// Create denominations
bool CPrivateSendClientSession::CreateDenominated(const CompactTallyItem& tallyItem, bool fCreateMixingCollaterals)
{
    if (!m_wallet_session) return false;

    std::vector<CRecipient> vecSend;
    CKeyHolderStorage keyHolderStorageDenom;

    CAmount nValueLeft = tallyItem.nAmount;
    nValueLeft -= CPrivateSend::GetCollateralAmount(); // leave some room for fees

    LogPrint(BCLog::PRIVSEND, "CreateDenominated step 1: %s nValueLeft: %f\n", EncodeDestination(tallyItem.txdest), (float)nValueLeft/COIN);

    // ****** Add an output for mixing collaterals ************ /

    if (fCreateMixingCollaterals) {
        std::shared_ptr<CReserveScript> scriptCollateral;
        keyHolderStorageDenom.AddKey(scriptCollateral, m_wallet_session);

        if (!scriptCollateral || scriptCollateral->reserveScript.empty()) {
            LogPrintf("CPrivateSendClientSession::CreateDenominated -- No script available, Keypool exhausted?\n");
            return false;
        }

        vecSend.push_back((CRecipient){ scriptCollateral->reserveScript, CPrivateSend::GetMaxCollateralAmount(), false });
        nValueLeft -= CPrivateSend::GetMaxCollateralAmount();
    }

    // ****** Add outputs for denoms ************ /

    // try few times - skipping smallest denoms first if there are too many of them already, if failed - use them too
    int nOutputsTotal = 0;
    bool fSkip = true;
    do {
        std::vector<CAmount> vecStandardDenoms = CPrivateSend::GetStandardDenominations();

        for (auto it = vecStandardDenoms.rbegin(); it != vecStandardDenoms.rend(); ++it) {
            CAmount nDenomValue = *it;

            if (fSkip) {
                // Note: denoms are skipped if there are already DENOMS_COUNT_MAX of them
                // and there are still larger denoms which can be used for mixing

                // check skipped denoms
                if (m_wallet_session->privateSendClient->IsDenomSkipped(nDenomValue)) {
                    LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CreateDenominated -- %s\n", strprintf("Too many %f denominations, skipping.", (float)nDenomValue / COIN));
                    continue;
                }

                // find new denoms to skip if any (ignore the largest one)
                if (nDenomValue != vecStandardDenoms.front() && m_wallet_session->CountInputsWithAmount(nDenomValue) > DENOMS_COUNT_MAX) {
                    LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::CreateDenominated -- %s\n", strprintf("Too many %f denominations, removing.", (float)nDenomValue/COIN));
                    m_wallet_session->privateSendClient->AddSkippedDenom(nDenomValue);
                    continue;
                }
            }

            int nOutputs = 0;

            // add each output up to 11 times until it can't be added again
            while(nValueLeft - nDenomValue >= 0 && nOutputs <= 10) {
                std::shared_ptr<CReserveScript> scriptDenom;
                keyHolderStorageDenom.AddKey(scriptDenom, m_wallet_session);

                if (!scriptDenom || scriptDenom->reserveScript.empty()) {
                    LogPrintf("CPrivateSendClientSession::CreateDenominated -- No script available, Keypool exhausted?\n");
                    return false;
                }

                vecSend.push_back((CRecipient){ scriptDenom->reserveScript, nDenomValue, false });

                //increment outputs and subtract denomination amount
                nOutputs++;
                nValueLeft -= nDenomValue;
                LogPrint(BCLog::PRIVSEND, "CreateDenominated step 2: totalOutputs: %d, nOutputsTotal: %d, nOutputs: %d, nValueLeft: %f\n", nOutputsTotal + nOutputs, nOutputsTotal, nOutputs, (float)nValueLeft/COIN);
            }

            nOutputsTotal += nOutputs;
            if (nValueLeft == 0) break;
        }
        LogPrint(BCLog::PRIVSEND, "CreateDenominated step 3: nOutputsTotal: %d, nValueLeft: %f\n", nOutputsTotal, (float)nValueLeft/COIN);
        // if there were no outputs added, start over without skipping
        fSkip = !fSkip;
    } while (nOutputsTotal == 0 && !fSkip);
    LogPrint(BCLog::PRIVSEND, "CreateDenominated step 4: nOutputsTotal: %d, nValueLeft: %f\n", nOutputsTotal, (float)nValueLeft/COIN);

    // No reasons to create mixing collaterals if we can't create denoms to mix
    if (nOutputsTotal == 0) return false;

    // if we have anything left over, it will be automatically send back as change - there is no need to send it manually

    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    // send change to the same address so that we were able create more denoms out of it later
    coinControl.destChange = tallyItem.txdest;
    for (const auto& outpoint : tallyItem.vecOutPoints)
        coinControl.Select(outpoint);

    CTransactionRef tx;
    CWalletTx wtx(m_wallet_session, tx);
    CAmount nFeeRet = 0;
    int nChangePosRet = -1;
    std::string strFail = "";
    // make our change address
    CReserveKey reservekeyChange(m_wallet_session);

    auto locked_chain = m_wallet_session->chain().lock();
    bool fSuccess = m_wallet_session->CreateTransaction(*locked_chain, vecSend, tx, reservekeyChange,
            nFeeRet, nChangePosRet, strFail, coinControl, true, ONLY_NONDENOMINATED);
    if (!fSuccess) {
        LogPrintf("CPrivateSendClientSession::CreateDenominated -- Error: %s\n", strFail);
        keyHolderStorageDenom.ReturnAll();
        return false;
    }

    keyHolderStorageDenom.KeepAll();

    CValidationState state;
    if (!m_wallet_session->CommitTransaction(tx, std::move(wtx.mapValue), {} /* orderForm */, reservekeyChange, g_connman.get(), state)) {
        LogPrintf("CPrivateSendClientSession::CreateDenominated -- CommitTransaction failed! Reason given: %s\n", state.GetRejectReason());
        return false;
    }

    // use the same nCachedLastSuccessBlock as for DS mixing to prevent race
    m_wallet_session->privateSendClient->UpdatedSuccessBlock();
    LogPrintf("CPrivateSendClientSession::CreateDenominated -- Success!\n");

    return true;
}

void CPrivateSendClientSession::RelayIn(const CPrivateSendEntry& entry)
{
    if (!infoMixingMasternode.fInfoValid) return;

    g_connman.get()->ForNode(infoMixingMasternode.addr, [&entry](CNode* pnode) {
        LogPrintf("CPrivateSendClientSession::RelayIn -- found master, relaying message to %s\n", pnode->addr.ToString());
        CNetMsgMaker msgMaker(pnode->GetSendVersion());
        g_connman.get()->PushMessage(pnode, msgMaker.Make(NetMsgType::DSVIN, entry));
        return true;
    });
}

void CPrivateSendClientSession::SetState(PoolState nStateNew)
{
    LogPrintf("CPrivateSendClientSession::SetState -- nState: %d, nStateNew: %d\n", nState, nStateNew);
    nState = nStateNew;
}

void CPrivateSendClientManager::UpdatedBlockTip(const int nHeight) {
    nCachedBlockHeight = nHeight;
    LogPrint(BCLog::PRIVSEND, "CPrivateSendClientSession::UpdatedBlockTip -- nCachedBlockHeight: %d\n", nCachedBlockHeight);
}

void CPrivateSendClientManager::ClientTask()
{
    if (fLiteMode || !masternodeSync.IsBlockchainSynced() || ShutdownRequested())
        return;

    static unsigned int nTick = 0;
    static unsigned int nDoAutoNextRun = nTick + PRIVATESEND_AUTO_TIMEOUT_MIN;

    if (fEnablePrivateSend) {
        CheckTimeout();
        ProcessPendingDsaRequest();
        nTick++;
        if (nDoAutoNextRun == nTick) {
            nDoAutoNextRun = nTick + PRIVATESEND_AUTO_TIMEOUT_MIN + GetRandInt(PRIVATESEND_AUTO_TIMEOUT_MAX - PRIVATESEND_AUTO_TIMEOUT_MIN);
            DoAutomaticDenominating();
        }
    }
}
