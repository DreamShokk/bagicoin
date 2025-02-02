// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <modules/masternode/masternode_man.h>

#include <addrman.h>
#include <clientversion.h>
#include <init.h>
#include <interfaces/chain.h>
#include <messagesigner.h>
#include <modules/platform/funding.h>
#include <modules/masternode/activemasternode.h>
#include <modules/masternode/masternode_payments.h>
#include <modules/masternode/masternode_sync.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <scheduler.h>
#include <script/standard.h>
#include <shutdown.h>
#include <ui_interface.h>
#include <util/system.h>
#include <warnings.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>

/** Masternode manager */
CMasternodeMan mnodeman;

const std::string CMasternodeMan::SERIALIZATION_VERSION_STRING = "CMasternodeMan-Version-7";
const int CMasternodeMan::LAST_PAID_SCAN_BLOCKS = 100;

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, const CMasternode*>& t1,
                    const std::pair<int, const CMasternode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->outpoint < t2.second->outpoint);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<arith_uint256, const CMasternode*>& t1,
                    const std::pair<arith_uint256, const CMasternode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->outpoint < t2.second->outpoint);
    }
};

struct CompareByAddr

{
    bool operator()(const CMasternode* t1,
                    const CMasternode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

CMasternodeMan::CMasternodeMan():
    cs(),
    mapMasternodes(),
    mAskedUsForMasternodeList(),
    mWeAskedForMasternodeList(),
    mWeAskedForMasternodeListEntry(),
    mWeAskedForVerification(),
    mMnbRecoveryRequests(),
    mMnbRecoveryGoodReplies(),
    listScheduledMnbRequestConnections(),
    fMasternodesAdded(false),
    fMasternodesRemoved(false),
    vecDirtyGovernanceObjectHashes(),
    nLastSentinelPingTime(0),
    mapSeenMasternodeBroadcast(),
    mapSeenMasternodePing()
{}

bool CMasternodeMan::Add(CMasternode &mn)
{
    LOCK(cs);

    if (Has(mn.outpoint)) return false;

    LogPrint(BCLog::MNODE, "CMasternodeMan::Add -- Adding new Masternode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
    uiInterface.NotifyMasternodeChanged(mn.outpoint, CT_NEW);
    mapMasternodes[mn.outpoint] = mn;
    fMasternodesAdded = true;
    return true;
}

void CMasternodeMan::AskForMN(CNode* pnode, const COutPoint& outpoint, CConnman* connman)
{
    if (!pnode) return;

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK(cs);

    CService addrSquashed = Params().AllowMultiplePorts() ? (CService)pnode->addr : CService(pnode->addr, 0);
    auto it1 = mWeAskedForMasternodeListEntry.find(outpoint);
    if (it1 != mWeAskedForMasternodeListEntry.end()) {
        auto it2 = it1->second.find(addrSquashed);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CMasternodeMan::AskForMN -- Asking same peer %s for missing masternode entry again: %s\n", addrSquashed.ToString(), outpoint.ToStringShort());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CMasternodeMan::AskForMN -- Asking new peer %s for missing masternode entry: %s\n", addrSquashed.ToString(), outpoint.ToStringShort());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrintf("CMasternodeMan::AskForMN -- Asking peer %s for missing masternode entry for the first time: %s\n", addrSquashed.ToString(), outpoint.ToStringShort());
    }
    mWeAskedForMasternodeListEntry[outpoint][addrSquashed] = GetTime() + DSEG_UPDATE_SECONDS;

    connman->PushMessage(pnode, msgMaker.Make(NetMsgType::DSEG, outpoint));
}

bool CMasternodeMan::PoSeBan(const COutPoint &outpoint)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    pmn->PoSeBan();

    return true;
}

void CMasternodeMan::Check()
{
    LOCK2(cs_main, cs);

    LogPrint(BCLog::MNODE, "CMasternodeMan::Check -- nLastSentinelPingTime=%d, IsSentinelPingActive()=%d\n", nLastSentinelPingTime, IsSentinelPingActive());

    for (auto& mnpair : mapMasternodes) {
        // NOTE: internally it checks only every MASTERNODE_CHECK_SECONDS seconds
        // since the last time, so expect some MNs to skip this
        mnpair.second.Check();
    }
}

void CMasternodeMan::CheckAndRemove(CConnman* connman)
{
    if (!masternodeSync.IsMasternodeListSynced()) return;

    LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateMasternodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent masternodes, prepare structures and make requests to reasure the state of inactive ones
        rank_pair_vec_t vecMasternodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES masternode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        std::map<COutPoint, CMasternode>::iterator it = mapMasternodes.begin();
        while (it != mapMasternodes.end()) {
            CMasternodeBroadcast mnb = CMasternodeBroadcast(it->second);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if (it->second.IsOutpointSpent()) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- Removing Masternode: %s  addr=%s  %i now\n", it->second.GetStateString(), it->second.addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenMasternodeBroadcast.erase(hash);
                mWeAskedForMasternodeListEntry.erase(it->first);

                // and finally remove it from the list
                it->second.FlagGovernanceItemsAsDirty();
                uiInterface.NotifyMasternodeChanged(it->first, CT_DELETED);
                mapMasternodes.erase(it++);
                fMasternodesRemoved = true;
            } else {
                bool fAsk = (nAskForMnbRecovery > 0) &&
                            masternodeSync.IsSynced() &&
                            it->second.IsNewStartRequired() &&
                            !IsMnbRecoveryRequested(hash) &&
                            !gArgs.IsArgSet("-connect");
                if (fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CService> setRequested;
                    // calulate only once and only when it's needed
                    if (vecMasternodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(nCachedBlockHeight);
                        GetMasternodeRanks(vecMasternodeRanks, nRandomBlockHeight);
                    }
                    bool fAskedForMnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL masternodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecMasternodeRanks.size(); i++) {
                        // avoid banning
                        if (mWeAskedForMasternodeListEntry.count(it->first) && mWeAskedForMasternodeListEntry[it->first].count(vecMasternodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecMasternodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledMnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForMnbRecovery = true;
                    }
                    if (fAskedForMnbRecovery) {
                        LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- Recovery initiated, masternode=%s\n", it->first.ToStringShort());
                        nAskForMnbRecovery--;
                    }
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for MASTERNODE_NEW_START_REQUIRED masternodes
        LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CMasternodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if (mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if (itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- reprocessing mnb, masternode=%s\n", itMnbReplies->second[0].outpoint.ToStringShort());
                    // mapSeenMasternodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateMasternodeList(nullptr, itMnbReplies->second[0], nDos, connman);
                }
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- removing mnb recovery reply, masternode=%s, size=%d\n", itMnbReplies->second[0].outpoint.ToStringShort(), (int)itMnbReplies->second.size());
                mMnbRecoveryGoodReplies.erase(itMnbReplies++);
            } else {
                ++itMnbReplies;
            }
        }
    }
    {
        // no need for cm_main below
        LOCK(cs);

        auto itMnbRequest = mMnbRecoveryRequests.begin();
        while(itMnbRequest != mMnbRecoveryRequests.end()){
            // Allow this mnb to be re-verified again after MNB_RECOVERY_RETRY_SECONDS seconds
            // if mn is still in MASTERNODE_NEW_START_REQUIRED state.
            if (GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Masternode list
        auto it1 = mAskedUsForMasternodeList.begin();
        while(it1 != mAskedUsForMasternodeList.end()){
            if ((*it1).second < GetTime()) {
                mAskedUsForMasternodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Masternode list
        it1 = mWeAskedForMasternodeList.begin();
        while(it1 != mWeAskedForMasternodeList.end()){
            if ((*it1).second < GetTime()){
                mWeAskedForMasternodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Masternodes we've asked for
        auto it2 = mWeAskedForMasternodeListEntry.begin();
        while(it2 != mWeAskedForMasternodeListEntry.end()){
            auto it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if (it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if (it2->second.empty()) {
                mWeAskedForMasternodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        auto it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if (it3->second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenMasternodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenMasternodePing
        std::map<uint256, CMasternodePing>::iterator it4 = mapSeenMasternodePing.begin();
        while(it4 != mapSeenMasternodePing.end()){
            if ((*it4).second.IsExpired()) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- Removing expired Masternode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenMasternodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenMasternodeVerification
        std::map<uint256, CMasternodeVerification>::iterator itv2 = mapSeenMasternodeVerification.begin();
        while(itv2 != mapSeenMasternodeVerification.end()){
            if ((*itv2).second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS){
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- Removing expired Masternode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenMasternodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrint(BCLog::MNODE, "CMasternodeMan::CheckAndRemove -- %s\n", ToString());
    }

    if (fMasternodesRemoved) {
        NotifyMasternodeUpdates(connman);
    }
}

void CMasternodeMan::Clear()
{
    LOCK(cs);
    mapMasternodes.clear();
    mAskedUsForMasternodeList.clear();
    mWeAskedForMasternodeList.clear();
    mWeAskedForMasternodeListEntry.clear();
    mapSeenMasternodeBroadcast.clear();
    mapSeenMasternodePing.clear();
    nLastSentinelPingTime = 0;
}

int CMasternodeMan::CountMasternodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinMasternodePaymentsProto() : nProtocolVersion;

    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CMasternodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinMasternodePaymentsProto() : nProtocolVersion;

    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.nProtocolVersion < nProtocolVersion || !mnpair.second.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

int CMasternodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    for (const auto& mnpair : mapMasternodes)
        if ((nNetworkType == NET_IPV4 && mnpair.second.addr.IsIPv4()) ||
            (nNetworkType == NET_ONION  && mnpair.second.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mnpair.second.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}

void CMasternodeMan::DsegUpdate(CNode* pnode, CConnman* connman)
{
    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    LOCK(cs);

    CService addrSquashed = Params().AllowMultiplePorts() ? (CService)pnode->addr : CService(pnode->addr, 0);
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            auto it = mWeAskedForMasternodeList.find(addrSquashed);
            if (it != mWeAskedForMasternodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CMasternodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", addrSquashed.ToString());
                return;
            }
        }
    }

    connman->PushMessage(pnode, msgMaker.Make(NetMsgType::DSEG, COutPoint()));

    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForMasternodeList[addrSquashed] = askAgain;

    LogPrint(BCLog::MNODE, "CMasternodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CMasternode* CMasternodeMan::Find(const COutPoint &outpoint)
{
    LOCK(cs);
    auto it = mapMasternodes.find(outpoint);
    return it == mapMasternodes.end() ? nullptr : &(it->second);
}

bool CMasternodeMan::Get(const COutPoint& outpoint, CMasternode& masternodeRet)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    auto it = mapMasternodes.find(outpoint);
    if (it == mapMasternodes.end()) {
        return false;
    }

    masternodeRet = it->second;
    return true;
}

bool CMasternodeMan::GetMasternodeInfo(const COutPoint& outpoint, masternode_info_t& mnInfoRet)
{
    LOCK(cs);
    auto it = mapMasternodes.find(outpoint);
    if (it == mapMasternodes.end()) {
        return false;
    }
    mnInfoRet = it->second.GetInfo();
    return true;
}

bool CMasternodeMan::GetMasternodeInfo(const CPubKey& pubKeyMasternode, masternode_info_t& mnInfoRet)
{
    LOCK(cs);
    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.pubKeyMasternode == pubKeyMasternode) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CMasternodeMan::GetMasternodeInfo(const CScript& payee, masternode_info_t& mnInfoRet)
{
    LOCK(cs);
    for (const auto& mnpair : mapMasternodes) {
        CScript scriptCollateralAddress = GetScriptForDestination(mnpair.second.pubKeyCollateralAddress.GetID());
        if (scriptCollateralAddress == payee) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CMasternodeMan::Has(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapMasternodes.find(outpoint) != mapMasternodes.end();
}

bool CMasternodeMan::HasBlockHash(uint256& hashRet, int nBlockHeight)
{
    if (chainActive.Tip() == nullptr) return false;
    if (nBlockHeight < -1 || nBlockHeight > chainActive.Height()) return false;
    if (nBlockHeight == -1) nBlockHeight = chainActive.Height();
    CBlockIndex* pblockindex = chainActive[nBlockHeight];
    hashRet = pblockindex->GetBlockHash();
    return true;
}

//
// Deterministically select the oldest/best masternode to pay on the network
//
bool CMasternodeMan::GetNextMasternodeInQueueForPayment(bool fFilterSigTime, int& nCountRet, masternode_info_t& mnInfoRet)
{
    return GetNextMasternodeInQueueForPayment(nCachedBlockHeight, fFilterSigTime, nCountRet, mnInfoRet);
}

bool CMasternodeMan::GetNextMasternodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCountRet, masternode_info_t& mnInfoRet)
{
    mnInfoRet = masternode_info_t();
    nCountRet = 0;

    if (!masternodeSync.IsWinnersListSynced()) {
        // without winner list we can't reliably find the next winner anyway
        return false;
    }

    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    std::vector<std::pair<int, const CMasternode*> > vecMasternodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nMnCount = CountMasternodes();

    for (const auto& mnpair : mapMasternodes) {
        if (!mnpair.second.IsValidForPayment()) continue;

        //check protocol version
        if (mnpair.second.nProtocolVersion < mnpayments.GetMinMasternodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (mnpayments.IsScheduled(mnpair.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if (fFilterSigTime && mnpair.second.sigTime + (nMnCount*2.6*60) > GetAdjustedTime()) continue;

        //check the output
        Coin coin;
        if (!pcoinsTip->GetCoin(mnpair.first, coin)) continue;

        //make sure it has at least as many confirmations as there are masternodes
        if ((chainActive.Height() - coin.nHeight + 1) < nMnCount) continue;

        vecMasternodeLastPaid.push_back(std::make_pair(mnpair.second.GetLastPaidBlock(), &mnpair.second));
    }

    nCountRet = (int)vecMasternodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if (fFilterSigTime && nCountRet < nMnCount/3)
        return GetNextMasternodeInQueueForPayment(nBlockHeight, false, nCountRet, mnInfoRet);

    // Sort them low to high
    std::sort(vecMasternodeLastPaid.begin(), vecMasternodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if (!HasBlockHash(blockHash, nBlockHeight - 101)) {
        LogPrintf("CMasternode::GetNextMasternodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight - 101);
        return false;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nMnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    const CMasternode *pBestMasternode = nullptr;
    for (const auto& s : vecMasternodeLastPaid) {
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if (nScore > nHighest){
            nHighest = nScore;
            pBestMasternode = s.second;
        }
        nCountTenth++;
        if (nCountTenth >= nTenthNetwork) break;
    }
    if (pBestMasternode) {
        mnInfoRet = pBestMasternode->GetInfo();
    }
    return mnInfoRet.fInfoValid;
}

masternode_info_t CMasternodeMan::FindRandomNotInVec(const std::vector<COutPoint> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinMasternodePaymentsProto() : nProtocolVersion;

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    LogPrintf("CMasternodeMan::FindRandomNotInVec -- %d enabled masternodes, %d masternodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if (nCountNotExcluded < 1) return masternode_info_t();

    // fill a vector of pointers
    std::vector<const CMasternode*> vpMasternodesShuffled;
    for (const auto& mnpair : mapMasternodes) {
        vpMasternodesShuffled.push_back(&mnpair.second);
    }

    // shuffle pointers
    Shuffle(vpMasternodesShuffled.begin(), vpMasternodesShuffled.end(), FastRandomContext());
    bool fExclude;

    // loop through
    for (const auto& pmn : vpMasternodesShuffled) {
        if (pmn->nProtocolVersion < nProtocolVersion || !pmn->IsEnabled()) continue;
        fExclude = false;
        for (const auto& outpointToExclude : vecToExclude) {
            if (pmn->outpoint == outpointToExclude) {
                fExclude = true;
                break;
            }
        }
        if (fExclude) continue;
        // found the one not in vecToExclude
        LogPrint(BCLog::MNODE, "CMasternodeMan::FindRandomNotInVec -- found, masternode=%s\n", pmn->outpoint.ToStringShort());
        return pmn->GetInfo();
    }

    LogPrint(BCLog::MNODE, "CMasternodeMan::FindRandomNotInVec -- failed\n");
    return masternode_info_t();
}

bool CMasternodeMan::GetMasternodeScores(const uint256& nBlockHash, CMasternodeMan::score_pair_vec_t& vecMasternodeScoresRet, int nMinProtocol)
{
    vecMasternodeScoresRet.clear();

    if (!masternodeSync.IsMasternodeListSynced())
        return false;

    AssertLockHeld(cs);

    if (mapMasternodes.empty())
        return false;

    // calculate scores
    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.nProtocolVersion >= nMinProtocol) {
            vecMasternodeScoresRet.push_back(std::make_pair(mnpair.second.CalculateScore(nBlockHash), &mnpair.second));
        }
    }

    std::sort(vecMasternodeScoresRet.rbegin(), vecMasternodeScoresRet.rend(), CompareScoreMN());
    return !vecMasternodeScoresRet.empty();
}

bool CMasternodeMan::GetMasternodeRank(const COutPoint& outpoint, int& nRankRet, int nBlockHeight, int nMinProtocol)
{
    nRankRet = -1;

    if (!masternodeSync.IsMasternodeListSynced())
        return false;

    // make sure we know about this block
    uint256 blockHash;
    if (!HasBlockHash(blockHash, nBlockHeight)) {
        LogPrintf("CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecMasternodeScores;
    if (!GetMasternodeScores(blockHash, vecMasternodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (const auto& scorePair : vecMasternodeScores) {
        nRank++;
        if (scorePair.second->outpoint == outpoint) {
            nRankRet = nRank;
            return true;
        }
    }

    return false;
}

bool CMasternodeMan::GetMasternodeRanks(CMasternodeMan::rank_pair_vec_t& vecMasternodeRanksRet, int nBlockHeight, int nMinProtocol)
{
    vecMasternodeRanksRet.clear();

    if (!masternodeSync.IsMasternodeListSynced())
        return false;

    // make sure we know about this block
    uint256 blockHash;
    if (!HasBlockHash(blockHash, nBlockHeight)) {
        LogPrintf("CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    LOCK(cs);

    score_pair_vec_t vecMasternodeScores;
    if (!GetMasternodeScores(blockHash, vecMasternodeScores, nMinProtocol))
        return false;

    int nRank = 0;
    for (const auto& scorePair : vecMasternodeScores) {
        nRank++;
        vecMasternodeRanksRet.push_back(std::make_pair(nRank, *scorePair.second));
    }

    return true;
}

void CMasternodeMan::ProcessMasternodeConnections(CConnman* connman)
{
    //we don't care about this for regtest
    if (Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    std::vector<CAddress> disconnect;
    std::vector<masternode_info_t> vecMnInfo;

    for (const auto& client : g_mn_interfaces->chain_clients) {
        std::vector<masternode_info_t> vecMnInfoClient;
        client->getMixingMasternodesInfo(vecMnInfoClient);
        vecMnInfo.reserve(vecMnInfo.size() + vecMnInfoClient.size());
        vecMnInfo.insert(vecMnInfo.end(), vecMnInfoClient.begin(), vecMnInfoClient.end());
    }

    connman->ForEachNode([&](CNode* pnode) {
        if (pnode->fMasternode) {
            bool ismixing = false;
            for (const auto& mnode : vecMnInfo) {
                if (mnode.addr == pnode->addr) ismixing = true;
            }
            if (!ismixing) {
                LogPrintf("CMasternodeMan::ProcessMasternodeConnections -- Closing Masternode connection: peer=%d, addr=%s\n", pnode->GetId(), pnode->addr.ToString());
                disconnect.push_back(pnode->addr);
                pnode->fDisconnect = true;
            } else {
                LogPrintf("CMasternodeMan::ProcessMasternodeConnections -- Keep mixing Masternode connection: peer=%d, addr=%s\n", pnode->GetId(), pnode->addr.ToString());
            }
        }
    });
    for (const auto& addr : disconnect){
        connman->RemovePendingMasternode(addr);
    }
}

std::pair<CService, std::set<uint256> > CMasternodeMan::PopScheduledMnbRequestConnection()
{
    LOCK(cs);
    if (listScheduledMnbRequestConnections.empty()) {
        return std::make_pair(CService(), std::set<uint256>());
    }

    std::set<uint256> setResult;

    listScheduledMnbRequestConnections.sort();
    std::pair<CService, uint256> pairFront = listScheduledMnbRequestConnections.front();

    // squash hashes from requests with the same CService as the first one into setResult
    std::list< std::pair<CService, uint256> >::iterator it = listScheduledMnbRequestConnections.begin();
    while(it != listScheduledMnbRequestConnections.end()) {
        if (pairFront.first == it->first) {
            setResult.insert(it->second);
            it = listScheduledMnbRequestConnections.erase(it);
        } else {
            // since list is sorted now, we can be sure that there is no more hashes left
            // to ask for from this addr
            break;
        }
    }
    return std::make_pair(pairFront.first, setResult);
}

void CMasternodeMan::ProcessPendingMnbRequests(CConnman* connman)
{
    std::pair<CService, std::set<uint256> > p = PopScheduledMnbRequestConnection();
    if (!(p.first == CService() || p.second.empty())) {
        if (connman->IsDisconnectRequested(p.first) || connman->IsMasternode(p.first)) return;
        mapPendingMNB.insert(std::make_pair(p.first, std::make_pair(GetTime(), p.second)));
        connman->AddPendingMasternode(p.first);
    }

    std::map<CService, std::pair<int64_t, std::set<uint256> > >::iterator itPendingMNB = mapPendingMNB.begin();
    while (itPendingMNB != mapPendingMNB.end()) {
        bool fDone = connman->ForNode(itPendingMNB->first, [&](CNode* pnode) {
            // compile request vector
            std::vector<CInv> vToFetch;
            for (auto& nHash : itPendingMNB->second.second) {
                if (nHash != uint256()) {
                    vToFetch.push_back(CInv(MSG_MASTERNODE_ANNOUNCE, nHash));
                    LogPrint(BCLog::MNODE, "-- asking for mnb %s from addr=%s\n", nHash.ToString(), pnode->addr.ToString());
                }
            }

            // ask for data
            CNetMsgMaker msgMaker(pnode->GetSendVersion());
            connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
            return true;
        });

        int64_t nTimeAdded = itPendingMNB->second.first;
        if (fDone || (GetTime() - nTimeAdded > 15)) {
            if (!fDone) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::%s -- failed to connect to %s\n", __func__, itPendingMNB->first.ToString());
            }
            mapPendingMNB.erase(itPendingMNB++);
        } else {
            ++itPendingMNB;
        }
    }
    LogPrint(BCLog::MNODE, "%s -- mapPendingMNB size: %d\n", __func__, mapPendingMNB.size());
}

void CMasternodeMan::ProcessModuleMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman)
{
    if (fLiteMode) return; // disable all Bagicoin specific functionality

    if (strCommand == NetMsgType::MNANNOUNCE) { //Masternode Broadcast

        CMasternodeBroadcast mnb;
        vRecv >> mnb;

        if (!masternodeSync.IsBlockchainSynced()) return;

        LogPrint(BCLog::MNODE, "MNANNOUNCE -- Masternode announce, masternode=%s\n", mnb.outpoint.ToStringShort());

        int nDos = 0;

        if (CheckMnbAndUpdateMasternodeList(pfrom, mnb, nDos, connman)) {
            // use announced Masternode as a peer
            std::vector<CAddress> vAddr;
            vAddr.push_back(CAddress(mnb.addr, NODE_NETWORK));
            connman->AddNewAddresses(vAddr, pfrom->addr, 2*60*60);
        } else if (nDos > 0) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), nDos);
        }

        if (fMasternodesAdded) {
            NotifyMasternodeUpdates(connman);
        }
    } else if (strCommand == NetMsgType::MNPING) { //Masternode Ping

        CMasternodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        if (!masternodeSync.IsBlockchainSynced()) return;

        LogPrint(BCLog::MNODE, "MNPING -- Masternode ping, masternode=%s\n", mnp.masternodeOutpoint.ToStringShort());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if (mapSeenMasternodePing.count(nHash)) return; //seen
        mapSeenMasternodePing.insert(std::make_pair(nHash, mnp));

        LogPrint(BCLog::MNODE, "MNPING -- Masternode ping, masternode=%s new\n", mnp.masternodeOutpoint.ToStringShort());

        // see if we have this Masternode
        CMasternode* pmn = Find(mnp.masternodeOutpoint);

        if (pmn && mnp.fSentinelIsCurrent)
            UpdateLastSentinelPingTime();

        // too late, new MNANNOUNCE is required
        if (pmn && pmn->IsNewStartRequired()) return;

        int nDos = 0;
        if (mnp.CheckAndUpdate(pmn, false, nDos, connman)) return;

        if (nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos);
        } else if (pmn != nullptr) {
            // nothing significant failed, mn is a known one too
            return;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a masternode entry once
        AskForMN(pfrom, mnp.masternodeOutpoint, connman);

    } else if (strCommand == NetMsgType::DSEG) { //Get Masternode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return;

        COutPoint masternodeOutpoint;

        vRecv >> masternodeOutpoint;

        LogPrint(BCLog::MNODE, "DSEG -- Masternode list, masternode=%s\n", masternodeOutpoint.ToStringShort());

        if (masternodeOutpoint.IsNull()) {
            SyncAll(pfrom, connman);
        } else {
            SyncSingle(pfrom, masternodeOutpoint);
        }

    } else if (strCommand == NetMsgType::MNVERIFY) { // Masternode Verify

        // Need LOCK2 here to ensure consistent locking order because all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CMasternodeVerification mnv;
        vRecv >> mnv;

        if (!masternodeSync.IsMasternodeListSynced()) return;

        if (mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv, connman);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some masternode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some masternode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
    }
}

void CMasternodeMan::SyncSingle(CNode* pnode, const COutPoint& outpoint)
{
    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    LOCK(cs);

    auto it = mapMasternodes.find(outpoint);

    if (it != mapMasternodes.end()) {
        if (it->second.addr.IsRFC1918() || it->second.addr.IsLocal()) return; // do not send local network masternode
        // NOTE: send masternode regardless of its current state, the other node will need it to verify old votes.
        LogPrint(BCLog::MNODE, "CMasternodeMan::%s -- Sending Masternode entry: masternode=%s  addr=%s\n", __func__, outpoint.ToStringShort(), it->second.addr.ToString());
        PushDsegInvs(pnode, it->second);
        LogPrintf("CMasternodeMan::%s -- Sent 1 Masternode inv to peer=%d\n", __func__, pnode->GetId());
    }
}

void CMasternodeMan::SyncAll(CNode* pnode, CConnman* connman)
{
    // do not provide any data until our node is synced
    if (!masternodeSync.IsSynced()) return;

    // local network
    bool isLocal = (pnode->addr.IsRFC1918() || pnode->addr.IsLocal());

    CService addrSquashed = Params().AllowMultiplePorts() ? (CService)pnode->addr : CService(pnode->addr, 0);
    // should only ask for this once
    if (!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
        LOCK2(cs_main, cs);
        auto it = mAskedUsForMasternodeList.find(addrSquashed);
        if (it != mAskedUsForMasternodeList.end() && it->second > GetTime()) {
            Misbehaving(pnode->GetId(), 34);
            LogPrintf("CMasternodeMan::%s -- peer already asked me for the list, peer=%d\n", __func__, pnode->GetId());
            return;
        }
        int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
        mAskedUsForMasternodeList[addrSquashed] = askAgain;
    }

    int nInvCount = 0;

    LOCK(cs);

    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.addr.IsRFC1918() || mnpair.second.addr.IsLocal()) continue; // do not send local network masternode
        // NOTE: send only ENABLED nodes as they are needed for payment verification. others can be processed
        // as pings and votes are distributed. This saves bandwidth and prevents the list from uncontrolled growth.
        if (mnpair.second.IsEnabled()) {
            LogPrint(BCLog::MNODE, "CMasternodeMan::%s -- Sending Masternode entry: masternode=%s  addr=%s\n", __func__, mnpair.first.ToStringShort(), mnpair.second.addr.ToString());
            PushDsegInvs(pnode, mnpair.second);
            nInvCount++;
        }
    }

    connman->PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_LIST, nInvCount));
    LogPrintf("CMasternodeMan::%s -- Sent %d Masternode invs to peer=%d\n", __func__, nInvCount, pnode->GetId());
}

void CMasternodeMan::PushDsegInvs(CNode* pnode, const CMasternode& mn)
{
    AssertLockHeld(cs);

    CMasternodeBroadcast mnb(mn);
    CMasternodePing mnp = mnb.lastPing;
    uint256 hashMNB = mnb.GetHash();
    uint256 hashMNP = mnp.GetHash();
    pnode->PushInventory(CInv(MSG_MASTERNODE_ANNOUNCE, hashMNB));
    pnode->PushInventory(CInv(MSG_MASTERNODE_PING, hashMNP));
    mapSeenMasternodeBroadcast.insert(std::make_pair(hashMNB, std::make_pair(GetTime(), mnb)));
    mapSeenMasternodePing.insert(std::make_pair(hashMNP, mnp));
}

// Verification of masternodes via unique direct requests.

void CMasternodeMan::DoFullVerificationStep(CConnman* connman)
{
    if (activeMasternode.outpoint.IsNull()) return;
    if (!masternodeSync.IsSynced()) return;

    rank_pair_vec_t vecMasternodeRanks;
    GetMasternodeRanks(vecMasternodeRanks, nCachedBlockHeight - 1, MIN_POSE_PROTO_VERSION);

    LOCK(cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecMasternodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    for (auto& rankPair : vecMasternodeRanks) {
        if (rankPair.first > MAX_POSE_RANK) {
            LogPrint(BCLog::MNODE, "CMasternodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                        (int)MAX_POSE_RANK);
            return;
        }
        if (rankPair.second.outpoint == activeMasternode.outpoint) {
            nMyRank = rankPair.first;
            LogPrint(BCLog::MNODE, "CMasternodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d masternodes\n",
                        nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
    }

    // edge case: list is too short and this masternode is not enabled
    if (nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS masternodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if (nOffset >= (int)vecMasternodeRanks.size()) return;

    std::vector<const CMasternode*> vSortedByAddr;
    for (const auto& mnpair : mapMasternodes) {
        vSortedByAddr.push_back(&mnpair.second);
    }

    std::sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    auto it = vecMasternodeRanks.begin() + nOffset;
    while(it != vecMasternodeRanks.end()) {
        if (it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint(BCLog::MNODE, "CMasternodeMan::DoFullVerificationStep -- Already %s%s%s masternode %s address %s, skipping...\n",
                        it->second.IsPoSeVerified() ? "verified" : "",
                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                        it->second.IsPoSeBanned() ? "banned" : "",
                        it->second.outpoint.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if (nOffset >= (int)vecMasternodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint(BCLog::MNODE, "CMasternodeMan::DoFullVerificationStep -- Verifying masternode %s rank %d/%d address %s\n",
                    it->second.outpoint.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if (SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr, connman)) {
            nCount++;
            if (nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if (nOffset >= (int)vecMasternodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }

    LogPrint(BCLog::MNODE, "CMasternodeMan::DoFullVerificationStep -- Sent verification requests to %d masternodes\n", nCount);
}

// This function tries to find masternodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CMasternodeMan::CheckSameAddr()
{
    if (!masternodeSync.IsSynced() || mapMasternodes.empty()) return;

    std::vector<CMasternode*> vBan;
    std::vector<CMasternode*> vSortedByAddr;

    {
        LOCK(cs);

        CMasternode* pprevMasternode = nullptr;
        CMasternode* pverifiedMasternode = nullptr;

        for (auto& mnpair : mapMasternodes) {
            vSortedByAddr.push_back(&mnpair.second);
        }

        std::sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        for (const auto& pmn : vSortedByAddr) {
            // check only (pre)enabled masternodes
            if (!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if (!pprevMasternode) {
                pprevMasternode = pmn;
                pverifiedMasternode = pmn->IsPoSeVerified() ? pmn : nullptr;
                continue;
            }
            // second+ step
            if (pmn->addr == pprevMasternode->addr) {
                if (pverifiedMasternode) {
                    // another masternode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if (pmn->IsPoSeVerified()) {
                    // this masternode with the same ip is verified, ban previous one
                    vBan.push_back(pprevMasternode);
                    // and keep a reference to be able to ban following masternodes with the same ip
                    pverifiedMasternode = pmn;
                }
            } else {
                pverifiedMasternode = pmn->IsPoSeVerified() ? pmn : nullptr;
            }
            pprevMasternode = pmn;
        }
    }

    // ban duplicates
    for (auto& pmn : vBan) {
        LogPrintf("CMasternodeMan::CheckSameAddr -- increasing PoSe ban score for masternode %s\n", pmn->outpoint.ToStringShort());
        pmn->IncreasePoSeBanScore();
    }
}

bool CMasternodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<const CMasternode*>& vSortedByAddr, CConnman* connman)
{
    if (netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint(BCLog::MNODE, "CMasternodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    if (connman->IsMasternode(addr) || connman->IsDisconnectRequested(addr)) return false;

    connman->AddPendingMasternode(addr);
    // use random nonce, store it and require node to reply with correct one later
    CMasternodeVerification mnv(addr, GetRandInt(999999), nCachedBlockHeight - 1);
    LOCK(cs_mapPendingMNV);
    mapPendingMNV.insert(std::make_pair(addr, std::make_pair(GetTime(), mnv)));
    LogPrintf("CMasternodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    return true;
}

void CMasternodeMan::ProcessPendingMnvRequests(CConnman* connman)
{
    LOCK(cs_mapPendingMNV);

    std::map<CService, std::pair<int64_t, CMasternodeVerification> >::iterator itPendingMNV = mapPendingMNV.begin();

    while (itPendingMNV != mapPendingMNV.end()) {
        bool fDone = connman->ForNode(itPendingMNV->first, [&](CNode* pnode) {
            netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
            // use random nonce, store it and require node to reply with correct one later
            mWeAskedForVerification[pnode->addr] = itPendingMNV->second.second;
            LogPrint(BCLog::MNODE, "-- verifying node using nonce %d addr=%s\n", itPendingMNV->second.second.nonce, pnode->addr.ToString());
            CNetMsgMaker msgMaker(pnode->GetSendVersion()); // TODO this gives a warning about version not being set (we should wait for VERSION exchange)
            connman->PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, itPendingMNV->second.second));
            return true;
        });

        int64_t nTimeAdded = itPendingMNV->second.first;
        if (fDone || (GetTime() - nTimeAdded > 15)) {
            if (!fDone) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::%s -- failed to connect to %s\n", __func__, itPendingMNV->first.ToString());
            }
            mapPendingMNV.erase(itPendingMNV++);
        } else {
            ++itPendingMNV;
        }
    }
    LogPrint(BCLog::MNODE, "%s -- mapPendingMNV size: %d\n", __func__, mapPendingMNV.size());
}

void CMasternodeMan::SendVerifyReply(CNode* pnode, CMasternodeVerification& mnv, CConnman* connman)
{
    AssertLockHeld(cs_main);

    // only masternodes can sign this, why would someone ask regular node?
    if (!fMasternodeMode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if (netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
        // peer should not ask us that often
        LogPrintf("MasternodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    uint256 blockHash;
    if (!HasBlockHash(blockHash, mnv.nBlockHeight)) {
        LogPrintf("MasternodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    std::string strError;

    uint256 hash = mnv.GetSignatureHash1(blockHash);

    if (!CHashSigner::SignHash(hash, activeMasternode.keyMasternode, mnv.vchSig1)) {
        LogPrintf("CMasternodeMan::SendVerifyReply -- SignHash() failed\n");
        return;
    }

    if (!CHashSigner::VerifyHash(hash, activeMasternode.pubKeyMasternode, mnv.vchSig1, strError)) {
        LogPrintf("CMasternodeMan::SendVerifyReply -- VerifyHash() failed, error: %s\n", strError);
        return;
    }

    CNetMsgMaker msgMaker(pnode->GetSendVersion());
    connman->PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, mnv));
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CMasternodeMan::ProcessVerifyReply(CNode* pnode, CMasternodeVerification& mnv)
{
    AssertLockHeld(cs_main);

    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if (!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if (mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if (mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    uint256 blockHash;
    if (!HasBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("MasternodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    // we already verified this address, why node is spamming?
    if (netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    {
        LOCK(cs);

        CMasternode* prealMasternode = nullptr;
        std::vector<CMasternode*> vpMasternodesToBan;

        uint256 hash1 = mnv.GetSignatureHash1(blockHash);
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(), mnv.nonce, blockHash.ToString());

        for (auto& mnpair : mapMasternodes) {
            if (CAddress(mnpair.second.addr, NODE_NETWORK) == pnode->addr) {
                bool fFound = false;
                fFound = CHashSigner::VerifyHash(hash1, mnpair.second.pubKeyMasternode, mnv.vchSig1, strError);
                if (fFound) {
                    // found it!
                    prealMasternode = &mnpair.second;
                    if (!mnpair.second.IsPoSeVerified()) {
                        mnpair.second.DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated masternode
                    if (activeMasternode.outpoint.IsNull()) continue;
                    // update ...
                    mnv.addr = mnpair.second.addr;
                    mnv.masternodeOutpoint1 = mnpair.second.outpoint;
                    mnv.masternodeOutpoint2 = activeMasternode.outpoint;
                    // ... and sign it
                    std::string strError;

                    uint256 hash2 = mnv.GetSignatureHash2(blockHash);

                    if (!CHashSigner::SignHash(hash2, activeMasternode.keyMasternode, mnv.vchSig2)) {
                        LogPrintf("MasternodeMan::ProcessVerifyReply -- SignHash() failed\n");
                        return;
                    }

                    if (!CHashSigner::VerifyHash(hash2, activeMasternode.pubKeyMasternode, mnv.vchSig2, strError)) {
                        LogPrintf("MasternodeMan::ProcessVerifyReply -- VerifyHash() failed, error: %s\n", strError);
                        return;
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mapSeenMasternodeVerification.insert(std::make_pair(mnv.GetHash(), mnv));
                    mnv.Relay();

                } else {
                    vpMasternodesToBan.push_back(&mnpair.second);
                }
            }
        }
        // no real masternode found?...
        if (!prealMasternode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CMasternodeMan::ProcessVerifyReply -- ERROR: no real masternode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->GetId(), 20);
            return;
        }
        LogPrintf("CMasternodeMan::ProcessVerifyReply -- verified real masternode %s for addr %s\n",
                    prealMasternode->outpoint.ToStringShort(), pnode->addr.ToString());
        // increase ban score for everyone else
        for (const auto& pmn : vpMasternodesToBan) {
            pmn->IncreasePoSeBanScore();
            LogPrint(BCLog::MNODE, "CMasternodeMan::ProcessVerifyReply -- increased PoSe ban score for %s addr %s, new score %d\n",
                        prealMasternode->outpoint.ToStringShort(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        if (!vpMasternodesToBan.empty())
            LogPrintf("CMasternodeMan::ProcessVerifyReply -- PoSe score increased for %d fake masternodes, addr %s\n",
                        (int)vpMasternodesToBan.size(), pnode->addr.ToString());
    }
}

void CMasternodeMan::ProcessVerifyBroadcast(CNode* pnode, const CMasternodeVerification& mnv)
{
    AssertLockHeld(cs_main);

    std::string strError;

    if (mapSeenMasternodeVerification.find(mnv.GetHash()) != mapSeenMasternodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenMasternodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if (mnv.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
        LogPrint(BCLog::MNODE, "CMasternodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                    nCachedBlockHeight, mnv.nBlockHeight, pnode->GetId());
        return;
    }

    if (mnv.masternodeOutpoint1 == mnv.masternodeOutpoint2) {
        LogPrint(BCLog::MNODE, "CMasternodeMan::ProcessVerifyBroadcast -- ERROR: same outpoints %s, peer=%d\n",
                    mnv.masternodeOutpoint1.ToStringShort(), pnode->GetId());
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->GetId(), 100);
        return;
    }

    uint256 blockHash;
    if (!HasBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    int nRank;

    if (!GetMasternodeRank(mnv.masternodeOutpoint2, nRank, mnv.nBlockHeight, MIN_POSE_PROTO_VERSION)) {
        LogPrint(BCLog::MNODE, "CMasternodeMan::ProcessVerifyBroadcast -- Can't calculate rank for masternode %s\n",
                    mnv.masternodeOutpoint2.ToStringShort());
        return;
    }

    if (nRank > MAX_POSE_RANK) {
        LogPrint(BCLog::MNODE, "CMasternodeMan::ProcessVerifyBroadcast -- Masternode %s is not in top %d, current rank %d, peer=%d\n",
                    mnv.masternodeOutpoint2.ToStringShort(), (int)MAX_POSE_RANK, nRank, pnode->GetId());
        return;
    }

    {
        LOCK(cs);

        CMasternode* pmn1 = Find(mnv.masternodeOutpoint1);
        if (!pmn1) {
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- can't find masternode1 %s\n", mnv.masternodeOutpoint1.ToStringShort());
            return;
        }

        CMasternode* pmn2 = Find(mnv.masternodeOutpoint2);
        if (!pmn2) {
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- can't find masternode2 %s\n", mnv.masternodeOutpoint2.ToStringShort());
            return;
        }

        if (pmn1->addr != mnv.addr) {
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- addr %s does not match %s\n", mnv.addr.ToString(), pmn1->addr.ToString());
            return;
        }

        uint256 hash1 = mnv.GetSignatureHash1(blockHash);
        uint256 hash2 = mnv.GetSignatureHash2(blockHash);

        if (!CHashSigner::VerifyHash(hash1, pmn1->pubKeyMasternode, mnv.vchSig1, strError)) {
            LogPrintf("MasternodeMan::ProcessVerifyBroadcast -- VerifyHash() failed, error: %s\n", strError);
            return;
        }

        if (!CHashSigner::VerifyHash(hash2, pmn2->pubKeyMasternode, mnv.vchSig2, strError)) {
            LogPrintf("MasternodeMan::ProcessVerifyBroadcast -- VerifyHash() failed, error: %s\n", strError);
            return;
        }

        if (!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- verified masternode %s for addr %s\n",
                    pmn1->outpoint.ToStringShort(), pmn1->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        for (auto& mnpair : mapMasternodes) {
            if (mnpair.second.addr != mnv.addr || mnpair.first == mnv.masternodeOutpoint1) continue;
            mnpair.second.IncreasePoSeBanScore();
            nCount++;
            LogPrint(BCLog::MNODE, "CMasternodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        mnpair.first.ToStringShort(), mnpair.second.addr.ToString(), mnpair.second.nPoSeBanScore);
        }
        if (nCount)
            LogPrintf("CMasternodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake masternodes, addr %s\n",
                        nCount, pmn1->addr.ToString());
    }
}

std::string CMasternodeMan::ToString() const
{
    std::ostringstream info;

    info << "Masternodes: " << (int)mapMasternodes.size() <<
            ", peers who asked us for Masternode list: " << (int)mAskedUsForMasternodeList.size() <<
            ", peers we asked for Masternode list: " << (int)mWeAskedForMasternodeList.size() <<
            ", entries in Masternode list we asked for: " << (int)mWeAskedForMasternodeListEntry.size();

    return info.str();
}

bool CMasternodeMan::CheckMnbAndUpdateMasternodeList(CNode* pfrom, CMasternodeBroadcast mnb, int& nDos, CConnman* connman)
{
    // Need to lock cs_main here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s\n", mnb.outpoint.ToStringShort());

        uint256 hash = mnb.GetHash();
        if (mapSeenMasternodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s seen\n", mnb.outpoint.ToStringShort());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if (GetTime() - mapSeenMasternodeBroadcast[hash].first > MASTERNODE_NEW_START_REQUIRED_SECONDS - MASTERNODE_MIN_MNP_SECONDS * 2) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s seen update\n", mnb.outpoint.ToStringShort());
                mapSeenMasternodeBroadcast[hash].first = GetTime();
                masternodeSync.BumpAssetLastTime("CMasternodeMan::CheckMnbAndUpdateMasternodeList - seen");
            }
            // did we ask this node for it?
            if (pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- mnb=%s seen request\n", hash.ToString());
                if (mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if (mnb.lastPing.sigTime > mapSeenMasternodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CMasternode mnTemp = CMasternode(mnb);
                        mnTemp.Check();
                        LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetAdjustedTime() - mnb.lastPing.sigTime)/60, mnTemp.GetStateString());
                        if (mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s seen good\n", mnb.outpoint.ToStringShort());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            uiInterface.NotifyMasternodeChanged(mnb.outpoint, CT_UPDATED);
            return true;
        }
        mapSeenMasternodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- masternode=%s new\n", mnb.outpoint.ToStringShort());

        if (!mnb.SimpleCheck(nDos)) {
            LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- SimpleCheck() failed, masternode=%s\n", mnb.outpoint.ToStringShort());
            return false;
        }

        // search Masternode list
        CMasternode* pmn = Find(mnb.outpoint);
        if (pmn) {
            CMasternodeBroadcast mnbOld = mapSeenMasternodeBroadcast[CMasternodeBroadcast(*pmn).GetHash()].second;
            if (!mnb.Update(pmn, nDos, connman)) {
                LogPrint(BCLog::MNODE, "CMasternodeMan::CheckMnbAndUpdateMasternodeList -- Update() failed, masternode=%s\n", mnb.outpoint.ToStringShort());
                return false;
            }
            if (hash != mnbOld.GetHash()) {
                mapSeenMasternodeBroadcast.erase(mnbOld.GetHash());
            }
            return true;
        }
    }

    if (mnb.CheckOutpoint(nDos)) {
        Add(mnb);
        masternodeSync.BumpAssetLastTime("CMasternodeMan::CheckMnbAndUpdateMasternodeList - new");
        // if it matches our Masternode privkey...
        if (fMasternodeMode && mnb.pubKeyMasternode == activeMasternode.pubKeyMasternode) {
            mnb.nPoSeBanScore = -MASTERNODE_POSE_BAN_MAX_SCORE;
            if (mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CMasternodeMan::CheckMnbAndUpdateMasternodeList -- Got NEW Masternode entry: masternode=%s  sigTime=%lld  addr=%s\n",
                            mnb.outpoint.ToStringShort(), mnb.sigTime, mnb.addr.ToString());
                activeMasternode.ManageState(connman);
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CMasternodeMan::CheckMnbAndUpdateMasternodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.Relay(connman);
    } else {
        LogPrintf("CMasternodeMan::CheckMnbAndUpdateMasternodeList -- Rejected Masternode entry: %s  addr=%s\n", mnb.outpoint.ToStringShort(), mnb.addr.ToString());
        return false;
    }
    return true;
}

void CMasternodeMan::UpdateLastPaid(const CBlockIndex* pindex)
{
    // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
    // in ReadBlockFromDisk
    LOCK2(cs_main, cs);

    if (fLiteMode || !masternodeSync.IsWinnersListSynced() || mapMasternodes.empty()) return;

    static int nLastRunBlockHeight = 0;
    // Scan at least LAST_PAID_SCAN_BLOCKS but no more than mnpayments.GetStorageLimit()
    int nMaxBlocksToScanBack = std::max(LAST_PAID_SCAN_BLOCKS, nCachedBlockHeight - nLastRunBlockHeight);
    nMaxBlocksToScanBack = std::min(nMaxBlocksToScanBack, mnpayments.GetStorageLimit());

    LogPrint(BCLog::MNODEPAY, "CMasternodeMan::UpdateLastPaid -- nCachedBlockHeight=%d, nLastRunBlockHeight=%d, nMaxBlocksToScanBack=%d\n",
                            nCachedBlockHeight, nLastRunBlockHeight, nMaxBlocksToScanBack);

    for (auto& mnpair : mapMasternodes) {
        mnpair.second.UpdateLastPaid(pindex, nMaxBlocksToScanBack);
    }

    nLastRunBlockHeight = nCachedBlockHeight;
}

void CMasternodeMan::UpdateLastSentinelPingTime()
{
    LOCK(cs);
    nLastSentinelPingTime = GetTime();
}

bool CMasternodeMan::IsSentinelPingActive()
{
    LOCK(cs);
    // Check if any masternodes have voted recently, otherwise return false
    return nLastSentinelPingTime == 0 ? false : (GetTime() - nLastSentinelPingTime) <= MASTERNODE_SENTINEL_PING_MAX_SECONDS;
}

bool CMasternodeMan::AddGovernanceVote(const COutPoint& outpoint, uint256 nGovernanceObjectHash)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if (!pmn) {
        return false;
    }
    pmn->AddGovernanceVote(nGovernanceObjectHash);
    return true;
}

void CMasternodeMan::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
{
    LOCK(cs);
    for(auto& mnpair : mapMasternodes) {
        mnpair.second.RemoveGovernanceObject(nGovernanceObjectHash);
    }
}

void CMasternodeMan::CheckMasternode(const CPubKey& pubKeyMasternode, bool fForce)
{
    LOCK2(cs_main, cs);
    for (auto& mnpair : mapMasternodes) {
        if (mnpair.second.pubKeyMasternode == pubKeyMasternode) {
            mnpair.second.Check(fForce);
            return;
        }
    }
}

bool CMasternodeMan::IsMasternodePingedWithin(const COutPoint& outpoint, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    return pmn ? pmn->IsPingedWithin(nSeconds, nTimeToCheckAt) : false;
}

void CMasternodeMan::SetMasternodeLastPing(const COutPoint& outpoint, const CMasternodePing& mnp)
{
    LOCK(cs);
    CMasternode* pmn = Find(outpoint);
    if (!pmn) {
        return;
    }
    pmn->lastPing = mnp;
    if (mnp.fSentinelIsCurrent) {
        UpdateLastSentinelPingTime();
    }
    mapSeenMasternodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CMasternodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (mapSeenMasternodeBroadcast.count(hash)) {
        mapSeenMasternodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CMasternodeMan::UpdatedBlockTip(const CBlockIndex *pindexNew)
{
    nCachedBlockHeight = pindexNew->nHeight;
    LogPrint(BCLog::MNODE, "CMasternodeMan::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    CheckSameAddr();

    if (fMasternodeMode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        UpdateLastPaid(pindexNew);
    }
}

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread mt(runCommand, strCmd); // thread runs free
}

static void DoWarning(const std::string& strWarning)
{
    static bool fWarned = false;
    SetMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

void CMasternodeMan::WarnMasternodeDaemonUpdates()
{
    LOCK(cs);

    static bool fWarned = false;

    if (fWarned || !size() || !masternodeSync.IsMasternodeListSynced())
        return;

    int nUpdatedMasternodes{0};

    for (const auto& mnpair : mapMasternodes) {
        if (mnpair.second.lastPing.nDaemonVersion > CLIENT_VERSION) {
            ++nUpdatedMasternodes;
        }
    }

    // Warn only when at least half of known masternodes already updated
    if (nUpdatedMasternodes < size() / 2)
        return;

    std::string strWarning;
    if (nUpdatedMasternodes != size()) {
        strWarning = strprintf(_("Warning: At least %d of %d masternodes are running on a newer software version. Please check latest releases, you might need to update too."),
                    nUpdatedMasternodes, size());
    } else {
        // someone was postponing this update for way too long probably
        strWarning = strprintf(_("Warning: Every masternode (out of %d known ones) is running on a newer software version. Please check latest releases, it's very likely that you missed a major/critical update."),
                    size());
    }

    // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user
    DoWarning(strWarning);
}

void CMasternodeMan::NotifyMasternodeUpdates(CConnman* connman)
{
    // Avoid double locking
    bool fMasternodesAddedLocal = false;
    bool fMasternodesRemovedLocal = false;
    {
        LOCK(cs);
        fMasternodesAddedLocal = fMasternodesAdded;
        fMasternodesRemovedLocal = fMasternodesRemoved;
    }

    if (fMasternodesAddedLocal) {
        funding.CheckMasternodeOrphanObjects(connman);
        funding.CheckMasternodeOrphanVotes(connman);
    }
    if (fMasternodesRemovedLocal) {
        funding.UpdateCachesAndClean();
    }

    LOCK(cs);
    fMasternodesAdded = false;
    fMasternodesRemoved = false;
}

void CMasternodeMan::ClientTask(CConnman* connman)
{
    if (fLiteMode) return; // disable all Dash specific functionality

    if (!masternodeSync.IsBlockchainSynced() || ShutdownRequested())
        return;

    static unsigned int nTick = 0;

    nTick++;

    // make sure to check all masternodes first
    mnodeman.Check();

    mnodeman.ProcessPendingMnbRequests(connman);
    mnodeman.ProcessPendingMnvRequests(connman);

    if (nTick % 60 == 0) {
        mnodeman.ProcessMasternodeConnections(connman);
        mnodeman.CheckAndRemove(connman);
        mnodeman.WarnMasternodeDaemonUpdates();
    }

    if (fMasternodeMode && (nTick % (60 * 5) == 0)) {
        mnodeman.DoFullVerificationStep(connman);
    }
}

void CMasternodeMan::Controller(CScheduler& scheduler, CConnman* connman)
{
    if (!fLiteMode) {
        scheduler.scheduleEvery(std::bind(&CMasternodeMan::ClientTask, this, connman), 1000);
    }
}

