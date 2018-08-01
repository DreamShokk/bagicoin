#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Partially Signed Transaction RPCs.
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, connect_nodes_bi, disconnect_nodes, find_output, sync_blocks

import json
import os

MAX_BIP125_RBF_SEQUENCE = 0xfffffffd

# Create one-input, one-output, no-fee transaction:
class PSCTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 3
       # TODO: remove -txindex. Currently required for getrawtransaction call.
        self.extra_args = [["-txindex"], ["-txindex"], ["-txindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_utxo_conversion(self):
        mining_node = self.nodes[2]
        offline_node = self.nodes[0]
        online_node = self.nodes[1]

        # Disconnect offline node from others
        disconnect_nodes(offline_node, 1)
        disconnect_nodes(online_node, 0)
        disconnect_nodes(offline_node, 2)
        disconnect_nodes(mining_node, 0)

        # Mine a transaction that credits the offline address
        offline_addr = offline_node.getnewaddress(address_type="p2sh-segwit")
        online_addr = online_node.getnewaddress(address_type="p2sh-segwit")
        online_node.importaddress(offline_addr, "", False)
        mining_node.sendtoaddress(address=offline_addr, amount=1.0)
        mining_node.generate(nblocks=1)
        sync_blocks([mining_node, online_node])

        # Construct an unsigned PSCT on the online node (who doesn't know the output is Segwit, so will include a non-witness UTXO)
        utxos = online_node.listunspent(addresses=[offline_addr])
        raw = online_node.createrawtransaction([{"txid":utxos[0]["txid"], "vout":utxos[0]["vout"]}],[{online_addr:0.9999}])
        psct = online_node.walletprocesspsct(online_node.converttopsct(raw))["psct"]
        assert("non_witness_utxo" in mining_node.decodepsct(psct)["inputs"][0])

        # Have the offline node sign the PSCT (which will update the UTXO to segwit)
        signed_psct = offline_node.walletprocesspsct(psct)["psct"]
        assert("witness_utxo" in mining_node.decodepsct(signed_psct)["inputs"][0])

        # Make sure we can mine the resulting transaction
        txid = mining_node.sendrawtransaction(mining_node.finalizepsct(signed_psct)["hex"])
        mining_node.generate(1)
        sync_blocks([mining_node, online_node])
        assert_equal(online_node.gettxout(txid,0)["confirmations"], 1)

        # Reconnect
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)

    def run_test(self):
        # Create and fund a raw tx for sending 10 BTC
        psctx1 = self.nodes[0].walletcreatefundedpsct([], {self.nodes[2].getnewaddress():10})['psct']

        # Node 1 should not be able to add anything to it but still return the psctx same as before
        psctx = self.nodes[1].walletprocesspsct(psctx1)['psct']
        assert_equal(psctx1, psctx)

        # Sign the transaction and send
        signed_tx = self.nodes[0].walletprocesspsct(psctx)['psct']
        final_tx = self.nodes[0].finalizepsct(signed_tx)['hex']
        self.nodes[0].sendrawtransaction(final_tx)

        # Create p2sh, p2wpkh, and p2wsh addresses
        pubkey0 = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())['pubkey']
        pubkey1 = self.nodes[1].getaddressinfo(self.nodes[1].getnewaddress())['pubkey']
        pubkey2 = self.nodes[2].getaddressinfo(self.nodes[2].getnewaddress())['pubkey']
        p2sh = self.nodes[1].addmultisigaddress(2, [pubkey0, pubkey1, pubkey2], "", "legacy")['address']
        p2wsh = self.nodes[1].addmultisigaddress(2, [pubkey0, pubkey1, pubkey2], "", "bech32")['address']
        p2sh_p2wsh = self.nodes[1].addmultisigaddress(2, [pubkey0, pubkey1, pubkey2], "", "p2sh-segwit")['address']
        p2wpkh = self.nodes[1].getnewaddress("", "bech32")
        p2pkh = self.nodes[1].getnewaddress("", "legacy")
        p2sh_p2wpkh = self.nodes[1].getnewaddress("", "p2sh-segwit")

        # fund those addresses
        rawtx = self.nodes[0].createrawtransaction([], {p2sh:10, p2wsh:10, p2wpkh:10, p2sh_p2wsh:10, p2sh_p2wpkh:10, p2pkh:10})
        rawtx = self.nodes[0].fundrawtransaction(rawtx, {"changePosition":3})
        signed_tx = self.nodes[0].signrawtransactionwithwallet(rawtx['hex'])['hex']
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.nodes[0].generate(6)
        self.sync_all()

        # Find the output pos
        p2sh_pos = -1
        p2wsh_pos = -1
        p2wpkh_pos = -1
        p2pkh_pos = -1
        p2sh_p2wsh_pos = -1
        p2sh_p2wpkh_pos = -1
        decoded = self.nodes[0].decoderawtransaction(signed_tx)
        for out in decoded['vout']:
            if out['scriptPubKey']['addresses'][0] == p2sh:
                p2sh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2wsh:
                p2wsh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2wpkh:
                p2wpkh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2sh_p2wsh:
                p2sh_p2wsh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2sh_p2wpkh:
                p2sh_p2wpkh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2pkh:
                p2pkh_pos = out['n']

        # spend single key from node 1
        rawtx = self.nodes[1].walletcreatefundedpsct([{"txid":txid,"vout":p2wpkh_pos},{"txid":txid,"vout":p2sh_p2wpkh_pos},{"txid":txid,"vout":p2pkh_pos}], {self.nodes[1].getnewaddress():29.99})['psct']
        walletprocesspsct_out = self.nodes[1].walletprocesspsct(rawtx)
        assert_equal(walletprocesspsct_out['complete'], True)
        self.nodes[1].sendrawtransaction(self.nodes[1].finalizepsct(walletprocesspsct_out['psct'])['hex'])

        # partially sign multisig things with node 1
        psctx = self.nodes[1].walletcreatefundedpsct([{"txid":txid,"vout":p2wsh_pos},{"txid":txid,"vout":p2sh_pos},{"txid":txid,"vout":p2sh_p2wsh_pos}], {self.nodes[1].getnewaddress():29.99})['psct']
        walletprocesspsct_out = self.nodes[1].walletprocesspsct(psctx)
        psctx = walletprocesspsct_out['psct']
        assert_equal(walletprocesspsct_out['complete'], False)

        # partially sign with node 2. This should be complete and sendable
        walletprocesspsct_out = self.nodes[2].walletprocesspsct(psctx)
        assert_equal(walletprocesspsct_out['complete'], True)
        self.nodes[2].sendrawtransaction(self.nodes[2].finalizepsct(walletprocesspsct_out['psct'])['hex'])

        # check that walletprocesspsct fails to decode a non-psct
        rawtx = self.nodes[1].createrawtransaction([{"txid":txid,"vout":p2wpkh_pos}], {self.nodes[1].getnewaddress():9.99})
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[1].walletprocesspsct, rawtx)

        # Convert a non-psct to psct and make sure we can decode it
        rawtx = self.nodes[0].createrawtransaction([], {self.nodes[1].getnewaddress():10})
        rawtx = self.nodes[0].fundrawtransaction(rawtx)
        new_psct = self.nodes[0].converttopsct(rawtx['hex'])
        self.nodes[0].decodepsct(new_psct)

        # Make sure that a psct with signatures cannot be converted
        signedtx = self.nodes[0].signrawtransactionwithwallet(rawtx['hex'])
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[0].converttopsct, signedtx['hex'])
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[0].converttopsct, signedtx['hex'], False)
        # Unless we allow it to convert and strip signatures
        self.nodes[0].converttopsct(signedtx['hex'], True)

        # Explicitly allow converting non-empty txs
        new_psct = self.nodes[0].converttopsct(rawtx['hex'])
        self.nodes[0].decodepsct(new_psct)

        # Create outputs to nodes 1 and 2
        node1_addr = self.nodes[1].getnewaddress()
        node2_addr = self.nodes[2].getnewaddress()
        txid1 = self.nodes[0].sendtoaddress(node1_addr, 13)
        txid2 =self.nodes[0].sendtoaddress(node2_addr, 13)
        self.nodes[0].generate(6)
        self.sync_all()
        vout1 = find_output(self.nodes[1], txid1, 13)
        vout2 = find_output(self.nodes[2], txid2, 13)

        # Create a psct spending outputs from nodes 1 and 2
        psct_orig = self.nodes[0].createpsct([{"txid":txid1,  "vout":vout1}, {"txid":txid2, "vout":vout2}], {self.nodes[0].getnewaddress():25.999})

        # Update pscts, should only have data for one input and not the other
        psct1 = self.nodes[1].walletprocesspsct(psct_orig)['psct']
        psct1_decoded = self.nodes[0].decodepsct(psct1)
        assert psct1_decoded['inputs'][0] and not psct1_decoded['inputs'][1]
        psct2 = self.nodes[2].walletprocesspsct(psct_orig)['psct']
        psct2_decoded = self.nodes[0].decodepsct(psct2)
        assert not psct2_decoded['inputs'][0] and psct2_decoded['inputs'][1]

        # Combine, finalize, and send the pscts
        combined = self.nodes[0].combinepsct([psct1, psct2])
        finalized = self.nodes[0].finalizepsct(combined)['hex']
        self.nodes[0].sendrawtransaction(finalized)
        self.nodes[0].generate(6)
        self.sync_all()

        # Test additional args in walletcreatepsct
        # Make sure both pre-included and funded inputs
        # have the correct sequence numbers based on
        # replaceable arg
        block_height = self.nodes[0].getblockcount()
        unspent = self.nodes[0].listunspent()[0]
        psctx_info = self.nodes[0].walletcreatefundedpsct([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], block_height+2, {"replaceable":True}, False)
        decoded_psct = self.nodes[0].decodepsct(psctx_info["psct"])
        for tx_in, psct_in in zip(decoded_psct["tx"]["vin"], decoded_psct["inputs"]):
           assert_equal(tx_in["sequence"], MAX_BIP125_RBF_SEQUENCE)
           assert "bip32_derivs" not in psct_in
        assert_equal(decoded_psct["tx"]["locktime"], block_height+2)

        # Same construction with only locktime set
        psctx_info = self.nodes[0].walletcreatefundedpsct([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], block_height, {}, True)
        decoded_psct = self.nodes[0].decodepsct(psctx_info["psct"])
        for tx_in, psct_in in zip(decoded_psct["tx"]["vin"], decoded_psct["inputs"]):
            assert tx_in["sequence"] > MAX_BIP125_RBF_SEQUENCE
            assert "bip32_derivs" in psct_in
        assert_equal(decoded_psct["tx"]["locktime"], block_height)

        # Same construction without optional arguments
        psctx_info = self.nodes[0].walletcreatefundedpsct([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}])
        decoded_psct = self.nodes[0].decodepsct(psctx_info["psct"])
        for tx_in in decoded_psct["tx"]["vin"]:
            assert tx_in["sequence"] > MAX_BIP125_RBF_SEQUENCE
        assert_equal(decoded_psct["tx"]["locktime"], 0)

        # Make sure change address wallet does not have P2SH innerscript access to results in success
        # when attempting BnB coin selection
        self.nodes[0].walletcreatefundedpsct([], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], block_height+2, {"changeAddress":self.nodes[1].getnewaddress()}, False)

        # Regression test for 14473 (mishandling of already-signed witness transaction):
        psctx_info = self.nodes[0].walletcreatefundedpsct([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}])
        complete_psct = self.nodes[0].walletprocesspsct(psctx_info["psct"])
        double_processed_psct = self.nodes[0].walletprocesspsct(complete_psct["psct"])
        assert_equal(complete_psct, double_processed_psct)
        # We don't care about the decode result, but decoding must succeed.
        self.nodes[0].decodepsct(double_processed_psct["psct"])

        # BIP 174 Test Vectors

        # Check that unknown values are just passed through
        unknown_psct = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA="
        unknown_out = self.nodes[0].walletprocesspsct(unknown_psct)['psct']
        assert_equal(unknown_psct, unknown_out)

        # Open the data file
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/rpc_psct.json'), encoding='utf-8') as f:
            d = json.load(f)
            invalids = d['invalid']
            valids = d['valid']
            creators = d['creator']
            signers = d['signer']
            combiners = d['combiner']
            finalizers = d['finalizer']
            extractors = d['extractor']

        # Invalid PSCTs
        for invalid in invalids:
            assert_raises_rpc_error(-22, "TX decode failed", self.nodes[0].decodepsct, invalid)

        # Valid PSCTs
        for valid in valids:
            self.nodes[0].decodepsct(valid)

        # Creator Tests
        for creator in creators:
            created_tx = self.nodes[0].createpsct(creator['inputs'], creator['outputs'])
            assert_equal(created_tx, creator['result'])

        # Signer tests
        for i, signer in enumerate(signers):
            self.nodes[2].createwallet("wallet{}".format(i))
            wrpc = self.nodes[2].get_wallet_rpc("wallet{}".format(i))
            for key in signer['privkeys']:
                wrpc.importprivkey(key)
            signed_tx = wrpc.walletprocesspsct(signer['psct'])['psct']
            assert_equal(signed_tx, signer['result'])

        # Combiner test
        for combiner in combiners:
            combined = self.nodes[2].combinepsct(combiner['combine'])
            assert_equal(combined, combiner['result'])

        # Empty combiner test
        assert_raises_rpc_error(-8, "Parameter 'txs' cannot be empty", self.nodes[0].combinepsct, [])

        # Finalizer test
        for finalizer in finalizers:
            finalized = self.nodes[2].finalizepsct(finalizer['finalize'], False)['psct']
            assert_equal(finalized, finalizer['result'])

        # Extractor test
        for extractor in extractors:
            extracted = self.nodes[2].finalizepsct(extractor['extract'], True)['hex']
            assert_equal(extracted, extractor['result'])

        # Unload extra wallets
        for i, signer in enumerate(signers):
            self.nodes[2].unloadwallet("wallet{}".format(i))

        self.test_utxo_conversion()

        # Test that pscts with p2pkh outputs are created properly
        p2pkh = self.nodes[0].getnewaddress(address_type='legacy')
        psct = self.nodes[1].walletcreatefundedpsct([], [{p2pkh : 1}], 0, {"includeWatching" : True}, True)
        self.nodes[0].decodepsct(psct['psct'])

        # Test decoding error: invalid base64
        assert_raises_rpc_error(-22, "TX decode failed invalid base64", self.nodes[0].decodepsct, ";definitely not base64;")

        # Send to all types of addresses
        addr1 = self.nodes[1].getnewaddress("", "bech32")
        txid1 = self.nodes[0].sendtoaddress(addr1, 11)
        vout1 = find_output(self.nodes[0], txid1, 11)
        addr2 = self.nodes[1].getnewaddress("", "legacy")
        txid2 = self.nodes[0].sendtoaddress(addr2, 11)
        vout2 = find_output(self.nodes[0], txid2, 11)
        addr3 = self.nodes[1].getnewaddress("", "p2sh-segwit")
        txid3 = self.nodes[0].sendtoaddress(addr3, 11)
        vout3 = find_output(self.nodes[0], txid3, 11)
        self.sync_all()

        # Update a PSCT with UTXOs from the node
        # Bech32 inputs should be filled with witness UTXO. Other inputs should not be filled because they are non-witness
        psct = self.nodes[1].createpsct([{"txid":txid1, "vout":vout1},{"txid":txid2, "vout":vout2},{"txid":txid3, "vout":vout3}], {self.nodes[0].getnewaddress():32.999})
        decoded = self.nodes[1].decodepsct(psct)
        assert "witness_utxo" not in decoded['inputs'][0] and "non_witness_utxo" not in decoded['inputs'][0]
        assert "witness_utxo" not in decoded['inputs'][1] and "non_witness_utxo" not in decoded['inputs'][1]
        assert "witness_utxo" not in decoded['inputs'][2] and "non_witness_utxo" not in decoded['inputs'][2]
        updated = self.nodes[1].utxoupdatepsct(psct)
        decoded = self.nodes[1].decodepsct(updated)
        assert "witness_utxo" in decoded['inputs'][0] and "non_witness_utxo" not in decoded['inputs'][0]
        assert "witness_utxo" not in decoded['inputs'][1] and "non_witness_utxo" not in decoded['inputs'][1]
        assert "witness_utxo" not in decoded['inputs'][2] and "non_witness_utxo" not in decoded['inputs'][2]

        # Two PSCTs with a common input should not be joinable
        psct1 = self.nodes[1].createpsct([{"txid":txid1, "vout":vout1}], {self.nodes[0].getnewaddress():Decimal('10.999')})
        assert_raises_rpc_error(-8, "exists in multiple PSCTs", self.nodes[1].joinpscts, [psct1, updated])

        # Join two distinct PSCTs
        addr4 = self.nodes[1].getnewaddress("", "p2sh-segwit")
        txid4 = self.nodes[0].sendtoaddress(addr4, 5)
        vout4 = find_output(self.nodes[0], txid4, 5)
        self.nodes[0].generate(6)
        self.sync_all()
        psct2 = self.nodes[1].createpsct([{"txid":txid4, "vout":vout4}], {self.nodes[0].getnewaddress():Decimal('4.999')})
        psct2 = self.nodes[1].walletprocesspsct(psct2)['psct']
        psct2_decoded = self.nodes[0].decodepsct(psct2)
        assert "final_scriptwitness" in psct2_decoded['inputs'][0] and "final_scriptSig" in psct2_decoded['inputs'][0]
        joined = self.nodes[0].joinpscts([psct, psct2])
        joined_decoded = self.nodes[0].decodepsct(joined)
        assert len(joined_decoded['inputs']) == 4 and len(joined_decoded['outputs']) == 2 and "final_scriptwitness" not in joined_decoded['inputs'][3] and "final_scriptSig" not in joined_decoded['inputs'][3]

        # Newly created PSCT needs UTXOs and updating
        addr = self.nodes[1].getnewaddress("", "p2sh-segwit")
        txid = self.nodes[0].sendtoaddress(addr, 7)
        addrinfo = self.nodes[1].getaddressinfo(addr)
        self.nodes[0].generate(6)
        self.sync_all()
        vout = find_output(self.nodes[0], txid, 7)
        psct = self.nodes[1].createpsct([{"txid":txid, "vout":vout}], {self.nodes[0].getnewaddress("", "p2sh-segwit"):Decimal('6.999')})
        analyzed = self.nodes[0].analyzepsct(psct)
        assert not analyzed['inputs'][0]['has_utxo'] and not analyzed['inputs'][0]['is_final'] and analyzed['inputs'][0]['next'] == 'updater' and analyzed['next'] == 'updater'

        # After update with wallet, only needs signing
        updated = self.nodes[1].walletprocesspsct(psct, False, 'ALL', True)['psct']
        analyzed = self.nodes[0].analyzepsct(updated)
        assert analyzed['inputs'][0]['has_utxo'] and not analyzed['inputs'][0]['is_final'] and analyzed['inputs'][0]['next'] == 'signer' and analyzed['next'] == 'signer' and analyzed['inputs'][0]['missing']['signatures'][0] == addrinfo['embedded']['witness_program']

        # Check fee and size things
        assert analyzed['fee'] == Decimal('0.001') and analyzed['estimated_vsize'] == 134 and analyzed['estimated_feerate'] == '0.00746268 BTC/kB'

        # After signing and finalizing, needs extracting
        signed = self.nodes[1].walletprocesspsct(updated)['psct']
        analyzed = self.nodes[0].analyzepsct(signed)
        assert analyzed['inputs'][0]['has_utxo'] and analyzed['inputs'][0]['is_final'] and analyzed['next'] == 'extractor'

if __name__ == '__main__':
    PSCTTest().main()
