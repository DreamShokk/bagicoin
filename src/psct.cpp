// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psct.h>
#include <util/strencodings.h>

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx) : tx(tx)
{
    inputs.resize(tx.vin.size());
    outputs.resize(tx.vout.size());
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psct)
{
    // Prohibited to merge two PSCTs over different transactions
    if (tx->GetHash() != psct.tx->GetHash()) {
        return false;
    }

    for (unsigned int i = 0; i < inputs.size(); ++i) {
        inputs[i].Merge(psct.inputs[i]);
    }
    for (unsigned int i = 0; i < outputs.size(); ++i) {
        outputs[i].Merge(psct.outputs[i]);
    }
    unknown.insert(psct.unknown.begin(), psct.unknown.end());

    return true;
}

bool PartiallySignedTransaction::IsSane() const
{
    for (PSCTInput input : inputs) {
        if (!input.IsSane()) return false;
    }
    return true;
}

bool PSCTInput::IsNull() const
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && redeem_script.empty() && witness_script.empty();
}

void PSCTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
}

void PSCTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
}

void PSCTInput::Merge(const PSCTInput& input)
{
    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
        non_witness_utxo = nullptr; // Clear out any non-witness utxo when we set a witness one.
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
}

bool PSCTInput::IsSane() const
{
    // Cannot have both witness and non-witness utxos
    if (!witness_utxo.IsNull() && non_witness_utxo) return false;

    // If we have a witness_script or a scriptWitness, we must also have a witness utxo
    if (!witness_script.empty() && witness_utxo.IsNull()) return false;
    if (!final_script_witness.IsNull() && witness_utxo.IsNull()) return false;

    return true;
}

void PSCTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
}

void PSCTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
}

bool PSCTOutput::IsNull() const
{
    return redeem_script.empty() && witness_script.empty() && hd_keypaths.empty() && unknown.empty();
}

void PSCTOutput::Merge(const PSCTOutput& output)
{
    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
}

bool PSCTInputSigned(PSCTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull();
}

bool SignPSCTInput(const SigningProvider& provider, PartiallySignedTransaction& psct, int index, int sighash)
{
    PSCTInput& input = psct.inputs.at(index);
    const CMutableTransaction& tx = *psct.tx;

    if (PSCTInputSigned(input)) {
        return true;
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    // Verify input sanity, which checks that at most one of witness or non-witness utxos is provided.
    if (!input.IsSane()) {
        return false;
    }

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = tx.vin[index].prevout;
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return false;
    }

    MutableTransactionSignatureCreator creator(&tx, index, utxo.nValue, sighash);
    sigdata.witness = false;
    bool sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return false;
    input.FromSignatureData(sigdata);

    // If we have a witness signature, use the smaller witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        input.non_witness_utxo = nullptr;
    }

    return sig_complete;
}

bool FinalizePSCT(PartiallySignedTransaction& psctx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    for (unsigned int i = 0; i < psctx.tx->vin.size(); ++i) {
        complete &= SignPSCTInput(DUMMY_SIGNING_PROVIDER, psctx, i, SIGHASH_ALL);
    }

    return complete;
}

bool FinalizeAndExtractPSCT(PartiallySignedTransaction& psctx, CMutableTransaction& result)
{
    // It's not safe to extract a PSCT that isn't finalized, and there's no easy way to check
    //   whether a PSCT is finalized without finalizing it, so we just do this.
    if (!FinalizePSCT(psctx)) {
        return false;
    }

    result = *psctx.tx;
    for (unsigned int i = 0; i < result.vin.size(); ++i) {
        result.vin[i].scriptSig = psctx.inputs[i].final_script_sig;
        result.vin[i].scriptWitness = psctx.inputs[i].final_script_witness;
    }
    return true;
}

bool CombinePSCTs(PartiallySignedTransaction& out, TransactionError& error, const std::vector<PartiallySignedTransaction>& psctxs)
{
    out = psctxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psctxs.begin()); it != psctxs.end(); ++it) {
        if (!out.Merge(*it)) {
            error = TransactionError::PSCT_MISMATCH;
            return false;
        }
    }
    if (!out.IsSane()) {
        error = TransactionError::INVALID_PSCT;
        return false;
    }

    return true;
}
