// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PSCTWALLET_H
#define BITCOIN_WALLET_PSCTWALLET_H

#include <psct.h>
#include <primitives/transaction.h>
#include <wallet/wallet.h>

bool FillPSCT(const CWallet* pwallet, PartiallySignedTransaction& psctx, int sighash_type = 1 /* SIGHASH_ALL */, bool sign = true, bool bip32derivs = false);

#endif // BITCOIN_WALLET_PSCTWALLET_H
