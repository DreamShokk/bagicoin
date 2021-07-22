// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/node.h>

#include <cachedb.h>
#include <amount.h>
#include <banman.h>
#include <chain.h>
#include <chainparams.h>
#include <init.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <modules/masternode/masternode_sync.h>
#include <modules/masternode/masternode_config.h>
#include <modules/masternode/masternode_man.h>
#include <modules/platform/funding.h>
#include <modules/platform/funding_validators.h>
#include <modules/coinjoin/coinjoin.h>
#include <modules/coinjoin/coinjoin_analyzer.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <rpc/server.h>
#include <scheduler.h>
#include <shutdown.h>
#include <sync.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>
#include <warnings.h>

#if defined(HAVE_CONFIG_H)
#include <config/bagicoin-config.h>
#endif

#include <atomic>
#include <univalue.h>

class CWallet;
fs::path GetWalletDir();
std::vector<fs::path> ListWalletDir();
std::vector<std::shared_ptr<CWallet>> GetWallets();
std::shared_ptr<CWallet> LoadWallet(interfaces::Chain& chain, const std::string& name, std::string& error, std::string& warning);

namespace interfaces {

class Wallet;

namespace {

Masternode MakeMasternode(const CMasternode& masternode)
{
    Masternode result;
    result.alias = "";
    for (const auto& mne : ::masternodeConfig.getEntries())
    {
        if ((COutPoint(uint256S(mne.getTxHash()), atoi(mne.getOutputIndex()))) == masternode.outpoint)
        {
            result.alias = mne.getAlias();
            break;
        }
    }
    result.outpoint = masternode.outpoint;
    result.address = masternode.addr.ToString();
    result.protocol = masternode.nProtocolVersion;
    result.daemon = masternode.lastPing.nDaemonVersion;
    result.sentinel = masternode.lastPing.nSentinelVersion;
    result.status = CMasternode::StateToString(masternode.nActiveState);
    result.active = masternode.lastPing.sigTime - masternode.sigTime;
    result.last_seen = masternode.lastPing.sigTime;
    result.payee = EncodeDestination(masternode.collDest);
    result.banscore = masternode.nPoSeBanScore;
    result.lastpaid = masternode.nTimeLastPaid;

    return result;
}

Proposal MakeProposal(const CGovernanceObject& pGovObj)
{
    Proposal result;
    if (pGovObj.GetObjectType() == GOVERNANCE_OBJECT_PROPOSAL) {
        UniValue objResult(UniValue::VOBJ);
        UniValue dataObj(UniValue::VOBJ);
        objResult.read(pGovObj.GetDataAsPlainString());

        std::vector<UniValue> arr1 = objResult.getValues();
        std::vector<UniValue> arr2 = arr1.at( 0 ).getValues();
        dataObj = arr2.at( 1 );

        result.hash = pGovObj.GetHash();
        result.start = dataObj["start_epoch"].get_int();
        result.end = dataObj["end_epoch"].get_int();
        result.yes = pGovObj.GetYesCount(VOTE_SIGNAL_FUNDING);
        result.no = pGovObj.GetNoCount(VOTE_SIGNAL_FUNDING);
        result.abs_yes = pGovObj.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING);
        result.amount = dataObj["payment_amount"].get_int64();
        result.name = dataObj["name"].get_str();
        result.url = dataObj["url"].get_str();
        result.funding = pGovObj.IsSetCachedFunding();
        result.endorsed = pGovObj.IsSetCachedEndorsed();

        return result;
    }
    return {};
}

class NodeImpl : public Node
{
public:
    NodeImpl() { m_interfaces.chain = MakeChain(); }
    bool parseParameters(int argc, const char* const argv[], std::string& error) override
    {
        return gArgs.ParseParameters(argc, argv, error);
    }
    bool readConfigFiles(std::string& error) override { return gArgs.ReadConfigFiles(error, true); }
    bool softSetArg(const std::string& arg, const std::string& value) override { return gArgs.SoftSetArg(arg, value); }
    bool softSetBoolArg(const std::string& arg, bool value) override { return gArgs.SoftSetBoolArg(arg, value); }
    void selectParams(const std::string& network) override { SelectParams(network); }
    uint64_t getAssumedBlockchainSize() override { return Params().AssumedBlockchainSize(); }
    uint64_t getAssumedChainStateSize() override { return Params().AssumedChainStateSize(); }
    std::string getNetwork() override { return Params().NetworkIDString(); }
    void initLogging() override { InitLogging(); }
    void initParameterInteraction() override { InitParameterInteraction(); }
    std::string getWarnings(const std::string& type) override { return GetWarnings(type); }
    uint32_t getLogCategories() override { return LogInstance().GetCategoryMask(); }
    bool baseInitialize() override
    {
        return AppInitBasicSetup() && AppInitParameterInteraction() && AppInitSanityChecks() &&
               AppInitLockDataDirectory();
    }
    bool appInitMain() override { return AppInitMain(m_interfaces); }
    void appShutdown() override
    {
        Interrupt();
        Shutdown(m_interfaces);
    }
    void startShutdown() override { StartShutdown(); }
    bool shutdownRequested() override { return ShutdownRequested(); }
    void mapPort(bool use_upnp) override
    {
        if (use_upnp) {
            StartMapPort();
        } else {
            InterruptMapPort();
            StopMapPort();
        }
    }
    void setupServerArgs() override { return SetupServerArgs(); }
    bool getProxy(Network net, proxyType& proxy_info) override { return GetProxy(net, proxy_info); }
    size_t getNodeCount(CConnman::NumConnections flags) override
    {
        return g_connman ? g_connman->GetNodeCount(flags) : 0;
    }
    bool getNodesStats(NodesStats& stats) override
    {
        stats.clear();

        if (g_connman) {
            std::vector<CNodeStats> stats_temp;
            g_connman->GetNodeStats(stats_temp);

            stats.reserve(stats_temp.size());
            for (auto& node_stats_temp : stats_temp) {
                stats.emplace_back(std::move(node_stats_temp), false, CNodeStateStats());
            }

            // Try to retrieve the CNodeStateStats for each node.
            TRY_LOCK(::cs_main, lockMain);
            if (lockMain) {
                for (auto& node_stats : stats) {
                    std::get<1>(node_stats) =
                        GetNodeStateStats(std::get<0>(node_stats).nodeid, std::get<2>(node_stats));
                }
            }
            return true;
        }
        return false;
    }
    bool getBanned(banmap_t& banmap) override
    {
        if (g_banman) {
            g_banman->GetBanned(banmap);
            return true;
        }
        return false;
    }
    bool ban(const CNetAddr& net_addr, BanReason reason, int64_t ban_time_offset) override
    {
        if (g_banman) {
            g_banman->Ban(net_addr, reason, ban_time_offset);
            return true;
        }
        return false;
    }
    bool unban(const CSubNet& ip) override
    {
        if (g_banman) {
            g_banman->Unban(ip);
            return true;
        }
        return false;
    }
    bool disconnect(const CNetAddr& net_addr) override
    {
        if (g_connman) {
            return g_connman->DisconnectNode(net_addr);
        }
        return false;
    }
    bool disconnect(NodeId id) override
    {
        if (g_connman) {
            return g_connman->DisconnectNode(id);
        }
        return false;
    }
    int64_t getTotalBytesRecv() override { return g_connman ? g_connman->GetTotalBytesRecv() : 0; }
    int64_t getTotalBytesSent() override { return g_connman ? g_connman->GetTotalBytesSent() : 0; }
    size_t getMempoolSize() override { return ::mempool.size(); }
    size_t getMempoolDynamicUsage() override { return ::mempool.DynamicMemoryUsage(); }
    bool getHeaderTip(int& height, int64_t& block_time) override
    {
        LOCK(::cs_main);
        if (::pindexBestHeader) {
            height = ::pindexBestHeader->nHeight;
            block_time = ::pindexBestHeader->GetBlockTime();
            return true;
        }
        return false;
    }
    int getNumBlocks() override
    {
        LOCK(::cs_main);
        return ::chainActive.Height();
    }
    int64_t getLastBlockTime() override
    {
        LOCK(::cs_main);
        if (::chainActive.Tip()) {
            return ::chainActive.Tip()->GetBlockTime();
        }
        return Params().GenesisBlock().GetBlockTime(); // Genesis block's time of current network
    }
    double getVerificationProgress() override
    {
        const CBlockIndex* tip;
        {
            LOCK(::cs_main);
            tip = ::chainActive.Tip();
        }
        if (!::masternodeSync.IsBlockchainSynced())
            return GuessVerificationProgress(Params().TxData(), tip);
        else
            return ::masternodeSync.getModuleSyncStatus();
    }
    bool isInitialBlockDownload() override { return IsInitialBlockDownload(); }
    bool isAddressTypeSet() override { return !::gArgs.GetArg("-addresstype", "").empty(); }
    bool getReindex() override { return ::fReindex; }
    bool getImporting() override { return ::fImporting; }
    void setNetworkActive(bool active) override
    {
        if (g_connman) {
            g_connman->SetNetworkActive(active);
        }
    }
    bool getNetworkActive() override { return g_connman && g_connman->GetNetworkActive(); }
    CAmount getMaxTxFee() override { return ::maxTxFee; }
    CFeeRate estimateSmartFee(int num_blocks, bool conservative, int* returned_target = nullptr) override
    {
        FeeCalculation fee_calc;
        CFeeRate result = ::feeEstimator.estimateSmartFee(num_blocks, &fee_calc, conservative);
        if (returned_target) {
            *returned_target = fee_calc.returnedTarget;
        }
        return result;
    }
    CFeeRate getDustRelayFee() override { return ::dustRelayFee; }
    UniValue executeRpc(const std::string& command, const UniValue& params, const std::string& uri) override
    {
        JSONRPCRequest req;
        req.params = params;
        req.strMethod = command;
        req.URI = uri;
        return ::tableRPC.execute(req);
    }
    std::vector<std::string> listRpcCommands() override { return ::tableRPC.listCommands(); }
    void rpcSetTimerInterfaceIfUnset(RPCTimerInterface* iface) override { RPCSetTimerInterfaceIfUnset(iface); }
    void rpcUnsetTimerInterface(RPCTimerInterface* iface) override { RPCUnsetTimerInterface(iface); }
    bool getUnspentOutput(const COutPoint& output, Coin& coin) override
    {
        LOCK(::cs_main);
        return ::pcoinsTip->GetCoin(output, coin);
    }
    //! Module signals

    std::string getModuleSyncStatus() override { return ::masternodeSync.GetSyncStatus(); }
    bool isMasternodeChainSynced() override { return ::masternodeSync.IsBlockchainSynced(); }
    bool isMasternodelistSynced() override { return ::masternodeSync.IsMasternodeListSynced(); }
    bool isModuleDataSynced() override { return ::masternodeSync.IsSynced(); }
    int getMasternodeConfigCount() override { return ::masternodeConfig.getCount(); }
    std::vector<CMasternodeConfig::CMasternodeEntry>& MNgetEntries() override { return ::masternodeConfig.getEntries(); }

    bool startMasternodeAlias(const std::string& strAlias, std::string& strErrorRet) override
    {
        for (const auto& mne : ::masternodeConfig.getEntries()) {
            if(mne.getAlias() == strAlias) {
                CMasternodeBroadcast mnb;
                if (!CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strErrorRet, mnb)) {
                    return false;
                }

                int nDoS = 0;
                if (!g_connman || !::mnodeman.CheckMnbAndUpdateMasternodeList(nullptr, mnb, nDoS, g_connman.get())) {
                    strErrorRet = "Failed to verify MNB";
                    return false;
                }
                ::mnodeman.NotifyMasternodeUpdates(g_connman.get());
                return true;
            }
        }
        strErrorRet = "Masternode not found";
        return false;
    }

    bool startAllMasternodes(const std::string& strCommand, std::string& strErrorRet, int& nCountSuccessful, int& nCountFailed) override
    {
        for (const auto& mne : ::masternodeConfig.getEntries()) {
            std::string strError;
            CMasternodeBroadcast mnb;

            int32_t nOutputIndex = 0;
            if(!ParseInt32(mne.getOutputIndex(), &nOutputIndex)) {
                continue;
            }

            COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), nOutputIndex);

            if(strCommand == "start-missing" && !::mnodeman.Has(outpoint)) continue;

            bool fSuccess = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), strError, mnb);

            int nDoS = 0;
            if (fSuccess && (!g_connman || !::mnodeman.CheckMnbAndUpdateMasternodeList(nullptr, mnb, nDoS, g_connman.get()))) {
                strError = "Failed to verify MNB";
                fSuccess = false;
            }
            if(fSuccess) {
                nCountSuccessful++;
                ::mnodeman.NotifyMasternodeUpdates(g_connman.get());
            } else {
                nCountFailed++;
                strErrorRet += "\nFailed to start " + mne.getAlias() + ". Error: " + strError;
            }
        }
        return true;
    }

    MasterNodeCount getMasternodeCount() override
    {
        MasterNodeCount result;
        result.size = ::mnodeman.size();
        result.compatible = ::mnodeman.CountMasternodes(MIN_COINJOIN_PEER_PROTO_VERSION);
        result.enabled = ::mnodeman.CountEnabled(-1);
        result.countIPv4 = ::mnodeman.CountByIP(NET_IPV4);
        result.countIPv6 = ::mnodeman.CountByIP(NET_IPV6);
        result.countTOR = ::mnodeman.CountByIP(NET_ONION);
        return result;
    }
    Masternode getMasternode(const COutPoint& outpoint) override
    {
        CMasternode masternodeRet;
        ::mnodeman.Get(outpoint, masternodeRet);
        return MakeMasternode(masternodeRet);
    }

    std::string getMasternodeKey(const std::string& alias) override
    {
        for (const auto& mne : ::masternodeConfig.getEntries())
        {
            if (alias == mne.getAlias())
                return mne.getPrivKey();
        }
        return {};
    }
    std::vector<Masternode> getMasternodes() override
    {
        std::vector<Masternode> result;
        std::map<COutPoint, CMasternode> mapMasternodes = mnodeman.GetFullMasternodeMap();
        for (const auto& mnpair : mapMasternodes)
        {
            CMasternode masternode = mnpair.second;
            result.emplace_back(MakeMasternode(masternode));
        }
        for (const auto& mne : ::masternodeConfig.getEntries())
        {
            bool fFound = false;
            for (const auto& mnpair : mapMasternodes)
            {
                CMasternode masternode = mnpair.second;
                if (masternode.outpoint == COutPoint(uint256S(mne.getTxHash()), atoi(mne.getOutputIndex())))
                {
                    fFound = true;
                    break;
                }
            }
            if (!fFound)
            {
                Masternode mineMissing;
                mineMissing.outpoint = COutPoint(uint256S(mne.getTxHash()), atoi(mne.getOutputIndex()));
                mineMissing.alias = mne.getAlias();
                mineMissing.address = mne.getIp();
                result.emplace_back(mineMissing);
            }
        }
        return result;
    }
    Proposal getProposal(const uint256& hash) override
    {
        LOCK(::funding.cs);
        CGovernanceObject* pGovObj = ::funding.FindGovernanceObject(hash);
        return MakeProposal(*pGovObj);
    }
    std::vector<Proposal> getProposals() override
    {
        std::vector<Proposal> result;
        std::vector<const CGovernanceObject*> objs = ::funding.GetAllNewerThan(0);
        for (const auto& pGovObj : objs)
        {
            if(pGovObj->GetObjectType() != GOVERNANCE_OBJECT_PROPOSAL) continue;
            result.emplace_back(MakeProposal(*pGovObj));
        }
        return result;
    }
    uint256 validateProposal(const std::string& data, const uint256 hash, CAmount& amount, std::string& error) override
    {
        const std::vector<unsigned char> dataHex(data.c_str(), data.c_str() + data.size() + 1);
        const std::string dataHexStr(HexStr(dataHex));
        int nRevision = 1;

        CProposalValidator validator(dataHexStr);

        if(!validator.Validate()) {
            error = validator.GetErrorMessages();
            return uint256();
        }

        CGovernanceObject govobj(uint256(), nRevision, GetTime(), hash, dataHexStr);

        if(hash == uint256()) {
            if (!govobj.IsValidLocally(error, false)) return uint256();
        }  else {
            bool fMissingMasternode;
            bool fMissingConfirmations;
            LOCK(::cs_main);
            if(!govobj.IsValidLocally(error, fMissingMasternode, fMissingConfirmations, true) && !fMissingConfirmations) return uint256();

            if(fMissingConfirmations) {
                funding.AddPostponedObject(govobj);
                govobj.Relay(g_connman.get());
            } else {
                funding.AddGovernanceObject(govobj, g_connman.get());
            }
        }
        amount = govobj.GetMinCollateralFee();
        return govobj.GetHash();
    }
    bool sendVoting(const uint256& hash, const std::pair<std::string, std::string>& strVoteSignal, std::pair<int, int>& nResult) override
    {
        return g_connman ? ::funding.VoteWithAll(hash, strVoteSignal, nResult, g_connman.get()) : false;
    }
    int analyzeCoin(const COutPoint& outpoint) override
    {
        return ::g_analyzer->AnalyzeCoin(outpoint);
    }
    std::string getWalletDir() override
    {
        return GetWalletDir().string();
    }
    std::vector<std::string> listWalletDir() override
    {
        std::vector<std::string> paths;
        for (auto& path : ListWalletDir()) {
            paths.push_back(path.string());
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const std::shared_ptr<CWallet>& wallet : GetWallets()) {
            wallets.emplace_back(MakeWallet(wallet));
        }
        return wallets;
    }
    std::unique_ptr<Wallet> loadWallet(const std::string& name, std::string& error, std::string& warning) override
    {
        return MakeWallet(LoadWallet(*m_interfaces.chain, name, error, warning));
    }
    std::unique_ptr<Handler> handleInitMessage(InitMessageFn fn) override
    {
        return MakeHandler(::uiInterface.InitMessage_connect(fn));
    }
    std::unique_ptr<Handler> handleMessageBox(MessageBoxFn fn) override
    {
        return MakeHandler(::uiInterface.ThreadSafeMessageBox_connect(fn));
    }
    std::unique_ptr<Handler> handleQuestion(QuestionFn fn) override
    {
        return MakeHandler(::uiInterface.ThreadSafeQuestion_connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeHandler(::uiInterface.ShowProgress_connect(fn));
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return MakeHandler(::uiInterface.LoadWallet_connect([fn](std::shared_ptr<CWallet> wallet) { fn(MakeWallet(wallet)); }));
    }
    std::unique_ptr<Handler> handleNotifyNumConnectionsChanged(NotifyNumConnectionsChangedFn fn) override
    {
        return MakeHandler(::uiInterface.NotifyNumConnectionsChanged_connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyNetworkActiveChanged(NotifyNetworkActiveChangedFn fn) override
    {
        return MakeHandler(::uiInterface.NotifyNetworkActiveChanged_connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyAlertChanged(NotifyAlertChangedFn fn) override
    {
        return MakeHandler(::uiInterface.NotifyAlertChanged_connect(fn));
    }
    std::unique_ptr<Handler> handleBannedListChanged(BannedListChangedFn fn) override
    {
        return MakeHandler(::uiInterface.BannedListChanged_connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyBlockTip(NotifyBlockTipFn fn) override
    {
        return MakeHandler(::uiInterface.NotifyBlockTip_connect([fn](bool initial_download, const CBlockIndex* block) {
            fn(initial_download, block->nHeight, block->GetBlockTime(),
                GuessVerificationProgress(Params().TxData(), block));
        }));
    }
    std::unique_ptr<Handler> handleNotifyHeaderTip(NotifyHeaderTipFn fn) override
    {
        return MakeHandler(
            ::uiInterface.NotifyHeaderTip_connect([fn](bool initial_download, const CBlockIndex* block) {
                fn(initial_download, block->nHeight, block->GetBlockTime(),
                    GuessVerificationProgress(Params().TxData(), block));
            }));
    }
    std::unique_ptr<Handler> handleMasternodeChanged(MasternodeChangedFn fn) override
    {
        return MakeHandler(::uiInterface.NotifyMasternodeChanged_connect(fn));
    }
    std::unique_ptr<Handler> handleProposalChanged(ProposalChangedFn fn) override
    {
        return MakeHandler(::uiInterface.NotifyProposalChanged_connect(fn));
    }
    InitInterfaces m_interfaces;
};

} // namespace

std::unique_ptr<Node> MakeNode() { return MakeUnique<NodeImpl>(); }

} // namespace interfaces
