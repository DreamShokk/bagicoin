Bagicoin Core *version* is now available from:

  <https://github.com/bagicoin/bagicoin/releases/tag/>

This is a new major version release, including new features, various bugfixes
and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bagicoin/bagicoin/issues>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Bagicoin-Qt` (on Mac)
or `bagicoind`/`bagicoin-qt` (on Linux).

The first time you run version 0.15.0 or newer, your chainstate database will be converted to a
new format, which will take anywhere from a few minutes to half an hour,
depending on the speed of your machine.

Note that the block database format also changed in version 0.8.0 and there is no
automatic upgrade code from before version 0.8 to version 0.15.0 or higher. Upgrading
directly from 0.7.x and earlier without re-downloading the blockchain is not supported.
However, as usual, old wallet versions are still supported.

Downgrading warning
-------------------

Wallets created in 0.16 and later are not compatible with versions prior to 0.16
and will not work if you try to use newly created wallets in older versions. Existing
wallets that were created with older versions are not affected by this.

Compatibility
==============

Bagicoin Core is supported and extensively tested on operating systems using
the Linux kernel, macOS 10.11+, and Windows 7 and newer.  It is not recommended
to use Bagicoin Core on unsupported systems.

Bagicoin Core should also work on most other Unix-like systems but is not
frequently tested on them.

From 0.17.0 onwards, macOS <10.11 is no longer supported.  0.17.0 is
built using Qt 5.9.x, which doesn't support versions of macOS older than
10.11.  Additionally, Bitcoin Core does not yet change appearance when
macOS "dark mode" is activated.

In addition to previously-supported CPU platforms, this release's
pre-compiled distribution also provides binaries for the RISC-V
platform.

Notable changes
===============

Mining
------

- Calls to `getblocktemplate` will fail if the segwit rule is not specified.
  Calling `getblocktemplate` without segwit specified is almost certainly
  a misconfiguration since doing so results in lower rewards for the miner.
  Failed calls will produce an error message describing how to enable the
  segwit rule.

Configuration option changes
----------------------------

- A warning is printed if an unrecognized section name is used in the
  configuration file.  Recognized sections are `[test]`, `[main]`, and
  `[regtest]`.

- Four new options are available for configuring the maximum number of
  messages that ZMQ will queue in memory (the "high water mark") before
  dropping additional messages.  The default value is 1,000, the same as
  was used for previous releases.  See the [ZMQ
  documentation](https://github.com/bagicoin/bagicoin/blob/master/doc/zmq.md#usage)
  for details.

- The `enablebip61` option (introduced in Bitcoin Core 0.16.99) is
  used to toggle sending of BIP 61 reject messages. Reject messages have no use
  case on the P2P network and are only logged for debugging by most network
  nodes. The option will now by default be off for improved privacy and security
  as well as reduced upload usage. The option can explicitly be turned on for
  local-network debugging purposes.

- The `rpcallowip` option can no longer be used to automatically listen
  on all network interfaces.  Instead, the `rpcbind` parameter must also
  be used to specify the IP addresses to listen on.  Listening for RPC
  commands over a public network connection is insecure and should be
  disabled, so a warning is now printed if a user selects such a
  configuration.  If you need to expose RPC in order to use a tool
  like Docker, ensure you only bind RPC to your localhost, e.g. `docker
  run [...] -p 127.0.0.1:8332:8332` (this is an extra `:8332` over the
  normal Docker port specification).

- The `rpcpassword` option now causes a startup error if the password
  set in the configuration file contains a hash character (#), as it's
  ambiguous whether the hash character is meant for the password or as a
  comment.

- The `whitelistforcerelay` option is used to relay transactions from
  whitelisted peers even when not accepted to the mempool. This option now
  defaults to being off, so that changes in policy and disconnect/ban behavior
  will not cause a node that is whitelisting another to be dropped by peers.
  Users can still explicitly enable this behavior with the command line option
  (and may want to consider [contacting](https://bitcoincore.org/en/contact/)
  the Bitcoin Core project to let us know about their
  use-case, as this feature could be deprecated in the future).

Documentation
-------------

- A new short
  [document](https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md)
  about the JSON-RPC interface describes cases where the results of an
  RPC might contain inconsistencies between data sourced from different
  subsystems, such as wallet state and mempool state.  A note is added
  to the [REST interface documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md)
  indicating that the same rules apply.

- Further information is added to the [JSON-RPC
  documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md)
  about how to secure this interface.

- A new [document](https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md)
  about the `bagicoin.conf` file describes how to use it to configure
  Bagicoin Core.

- A new document introduces Bitcoin Core's BIP174
  [Partially-Signed Bagicoin Transactions (PSBT)](https://github.com/bagicoin/bagicoin/blob/master/doc/psbt.md)
  interface, which is used to allow multiple programs to collaboratively
  work to create, sign, and broadcast new transactions.  This is useful
  for offline (cold storage) wallets, multisig wallets, coinjoin
  implementations, and many other cases where two or more programs need
  to interact to generate a complete transaction.

- The [output script descriptor](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
  documentation has been updated with information about new features in
  this still-developing language for describing the output scripts that
  a wallet or other program wants to receive notifications for, such as
  which addresses it wants to know received payments.  The language is
  currently used in the `scantxoutset` RPC and is expected to be adapted
  to other RPCs and to the underlying wallet structure.

Build system changes
--------------------

- A new `--disable-bip70` option may be passed to `./configure` to
  prevent Bitcoin-Qt from being built with support for the BIP70 payment
  protocol or from linking libssl.  As the payment protocol has exposed
  Bitcoin Core to libssl vulnerabilities in the past, builders who don't
  need BIP70 support are encouraged to use this option to reduce their
  exposure to future vulnerabilities.

Deprecated or removed RPCs
--------------------------

### Low-level changes

- The `createrawtransaction` RPC will now accept an array or dictionary (kept for compatibility) for the `outputs` parameter. This means the order of transaction outputs can be specified by the client.
- The `fundrawtransaction` RPC will reject the previously deprecated `reserveChangeKey` option.
- `sendmany` now shuffles outputs to improve privacy, so any previously expected behavior with regards to output ordering can no longer be relied upon.
- The new RPC `testmempoolaccept` can be used to test acceptance of a transaction to the mempool without adding it.
- JSON transaction decomposition now includes a `weight` field which provides
the transaction's exact weight. This is included in REST /rest/tx/ and
/rest/block/ endpoints when in json mode. This is also included in `getblock`
(with verbosity=2), `listsinceblock`, `listtransactions`, and
`getrawtransaction` RPC commands.
- New `fees` field introduced in `getrawmempool`, `getmempoolancestors`, `getmempooldescendants` and
`getmempoolentry` when verbosity is set to `true` with sub-fields `ancestor`, `base`, `modified`
and `descendant` denominated in BTC. This new field deprecates previous fee fields, such as
`fee`, `modifiedfee`, `ancestorfee` and `descendantfee`.
- The new RPC `getzmqnotifications` returns information about active ZMQ
notifications.

External wallet files
---------------------

The `-wallet=<path>` option now accepts full paths instead of requiring wallets
to be located in the -walletdir directory.

Newly created wallet format
---------------------------

If `-wallet=<path>` is specified with a path that does not exist, it will now
create a wallet directory at the specified location (containing a wallet.dat
data file, a db.log file, and database/log.?????????? files) instead of just
creating a data file at the path and storing log files in the parent
directory. This should make backing up wallets more straightforward than
before because the specified wallet path can just be directly archived without
having to look in the parent directory for transaction log files.

For backwards compatibility, wallet paths that are names of existing data files
in the `-walletdir` directory will continue to be accepted and interpreted the
same as before.

Dynamic loading and creation of wallets
---------------------------------------

Previously, wallets could only be loaded or created at startup, by specifying `-wallet` parameters on the command line or in the bagicoin.conf file. It is now possible to load, create and unload wallets dynamically at runtime:

- Existing wallets can be loaded by calling the `loadwallet` RPC. The wallet can be specified as file/directory basename (which must be located in the `walletdir` directory), or as an absolute path to a file/directory.
- New wallets can be created (and loaded) by calling the `createwallet` RPC. The provided name must not match a wallet file in the `walletdir` directory or the name of a wallet that is currently loaded.
- Loaded wallets can be unloaded by calling the `unloadwallet` RPC.

This feature is currently only available through the RPC interface.

Coin selection
--------------
- A new `-avoidpartialspends` flag has been added (default=false). If enabled, the wallet will try to spend UTXO's that point at the same destination
together. This is a privacy increase, as there will no longer be cases where a wallet will inadvertently spend only parts of the coins sent to
the same address (note that if someone were to send coins to that address after it was used, those coins will still be included in future
coin selections).

Configuration sections for testnet and regtest
----------------------------------------------

It is now possible for a single configuration file to set different
options for different networks. This is done by using sections or by
prefixing the option with the network, such as:

main.uacomment=bagicoin
test.uacomment=bagicoin-testnet
regtest.uacomment=regtest
[main]
mempoolsize=300
[test]
mempoolsize=100
[regtest]
mempoolsize=20

The `addnode=`, `connect=`, `port=`, `bind=`, `rpcport=`, `rpcbind=`
and `wallet=` options will only apply to mainnet when specified in the
configuration file, unless a network is specified.

'label' and 'account' APIs for wallet
-------------------------------------

A new 'label' API has been introduced for the wallet. This is intended as a
replacement for the deprecated 'account' API. The 'account' can continue to
be used in V0.17 by starting bagicoind with the '-deprecatedrpc=accounts'
argument, and will be fully removed in V0.18.

The label RPC methods mirror the account functionality, with the following functional differences:

- Labels can be set on any address, not just receiving addresses. This functionality was previously only available through the GUI.
- Labels can be deleted by reassigning all addresses using the `setlabel` RPC method.
- There isn't support for sending transactions _from_ a label, or for determining which label a transaction was sent from.
- Labels do not have a balance.

Here are the changes to RPC methods:

| Deprecated Method       | New Method            | Notes       |
| :---------------------- | :-------------------- | :-----------|
| `getaccount`            | `getaddressinfo`      | `getaddressinfo` returns a json object with address information instead of just the name of the account as a string. |
| `getaccountaddress`     | n/a                   | There is no replacement for `getaccountaddress` since labels do not have an associated receive address. |
| `getaddressesbyaccount` | `getaddressesbylabel` | `getaddressesbylabel` returns a json object with the addresses as keys, instead of a list of strings. |
| `getreceivedbyaccount`  | `getreceivedbylabel`  | _no change in behavior_ |
| `listaccounts`          | `listlabels`          | `listlabels` does not return a balance or accept `minconf` and `watchonly` arguments. |
| `listreceivedbyaccount` | `listreceivedbylabel` | Both methods return new `label` fields, along with `account` fields for backward compatibility. |
| `move`                  | n/a                   | _no replacement_ |
| `sendfrom`              | n/a                   | _no replacement_ |
| `setaccount`            | `setlabel`            | Both methods now: <ul><li>allow assigning labels to any address, instead of raising an error if the address is not receiving address.<li>delete the previous label associated with an address when the final address using that label is reassigned to a different label, instead of making an implicit `getaccountaddress` call to ensure the previous label still has a receiving address. |

| Changed Method         | Notes   |
| :--------------------- | :------ |
| `addmultisigaddress`   | Renamed `account` named parameter to `label`. Still accepts `account` for backward compatibility if running with '-deprecatedrpc=accounts'. |
| `getnewaddress`        | Renamed `account` named parameter to `label`. Still accepts `account` for backward compatibility. if running with '-deprecatedrpc=accounts' |
| `listunspent`          | Returns new `label` fields. `account` field will be returned for backward compatibility if running with '-deprecatedrpc=accounts' |
| `sendmany`             | The `account` named parameter has been renamed to `dummy`. If provided, the `dummy` parameter must be set to the empty string, unless running with the `-deprecatedrpc=accounts` argument (in which case functionality is unchanged). |
| `listtransactions`     | The `account` named parameter has been renamed to `dummy`. If provided, the `dummy` parameter must be set to the string `*`, unless running with the `-deprecatedrpc=accounts` argument (in which case functionality is unchanged). |
| `getbalance`           | `account`, `minconf` and `include_watchonly` parameters are deprecated, and can only be used if running with '-deprecatedrpc=accounts' |

Low-level RPC changes
---------------------

- When bagicoin is not started with any `-wallet=<path>` options, the name of
the default wallet returned by `getwalletinfo` and `listwallets` RPCs is
now the empty string `""` instead of `"wallet.dat"`. If bagicoin is started
with any `-wallet=<path>` options, there is no change in behavior, and the
name of any wallet is just its `<path>` string.
- Passing an empty string (`""`) as the `address_type` parameter to
`getnewaddress`, `getrawchangeaddress`, `addmultisigaddress`,
`fundrawtransaction` RPCs is now an error. Previously, this would fall back
to using the default address type. It is still possible to pass null or leave
the parameter unset to use the default address type.

- Bare multisig outputs to our keys are no longer automatically treated as
incoming payments. As this feature was only available for multisig outputs for
which you had all private keys in your wallet, there was generally no use for
them compared to single-key schemes. Furthermore, no address format for such
outputs is defined, and wallet software can't easily send to it. These outputs
will no longer show up in `listtransactions`, `listunspent`, or contribute to
your balance, unless they are explicitly watched (using `importaddress` or
`importmulti` with hex script argument). `signrawtransaction*` also still
works for them.

- The `getwalletinfo` RPC method now returns an `hdseedid` value, which is always the same as the incorrectly-named `hdmasterkeyid` value. `hdmasterkeyid` will be removed in V0.18.
- The `getaddressinfo` RPC method now returns an `hdseedid` value, which is always the same as the incorrectly-named `hdmasterkeyid` value. `hdmasterkeyid` will be removed in V0.18.

Other API changes
-----------------

- The `inactivehdmaster` property in the `dumpwallet` output has been corrected to `inactivehdseed`

### Logging

- The log timestamp format is now ISO 8601 (e.g. "2018-02-28T12:34:56Z").

- When running bagicoind with `-debug` but without `-daemon`, logging to stdout
is now the default behavior. Setting `-printtoconsole=1` no longer implicitly
disables logging to debug.log. Instead, logging to file can be explicitly disabled
by setting `-debuglogfile=0`.

Transaction index changes
-------------------------

The transaction index is now built separately from the main node procedure,
meaning the `-txindex` flag can be toggled without a full reindex. If bagicoind
is run with `-txindex` on a node that is already partially or fully synced
without one, the transaction index will be built in the background and become
available once caught up. When switching from running `-txindex` to running
without the flag, the transaction index database will *not* be deleted
automatically, meaning it could be turned back on at a later time without a full
resync.

Miner block size removed
------------------------

The `-blockmaxsize` option for miners to limit their blocks' sizes was
deprecated in V0.15.1, and has now been removed. Miners should use the
`-blockmaxweight` option if they want to limit the weight of their blocks'
weights.

Python Support
--------------

Support for Python 2 has been discontinued for all test files and tools.
=======
- The `signrawtransaction` RPC is removed after being deprecated and
  hidden behind a special configuration option in version 0.17.0.

- The 'account' API is removed after being deprecated in v0.17.  The
  'label' API was introduced in v0.17 as a replacement for accounts.
  See the [release notes from v0.17](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.17.0.md#label-and-account-apis-for-wallet)
  for a full description of the changes from the 'account' API to the
  'label' API.

- The `addwitnessaddress` RPC is removed after being deprecated in
  version 0.13.0.

- The wallet's `generate` RPC method is deprecated and will be fully
  removed in a subsequent major version.  This RPC is only used for
  testing, but its implementation reached across multiple subsystems
  (wallet and mining), so it is being deprecated to simplify the
  wallet-node interface.  Projects that are using `generate` for testing
  purposes should transition to using the `generatetoaddress` RPC, which
  does not require or use the wallet component. Calling
  `generatetoaddress` with an address returned by the `getnewaddress`
  RPC gives the same functionality as the old `generate` RPC.  To
  continue using `generate` in this version, restart bitcoind with the
  `-deprecatedrpc=generate` configuration option.

New RPCs
--------

- The `getnodeaddresses` RPC returns peer addresses known to this
  node. It may be used to find nodes to connect to without using a DNS
  seeder.

- The `listwalletdir` RPC returns a list of wallets in the wallet
  directory (either the default wallet directory or the directory
  configured by the `-walletdir` parameter).

- The `getrpcinfo` returns runtime details of the RPC server. At the
  moment, it returns an array of the currently active commands and how
  long they've been running.

Updated RPCs
------------

Note: some low-level RPC changes mainly useful for testing are described
in the Low-level Changes section below.

- The `getpeerinfo` RPC now returns an additional `minfeefilter` field
  set to the peer's BIP133 fee filter.  You can use this to detect that
  you have peers that are willing to accept transactions below the
  default minimum relay fee.

- The mempool RPCs, such as `getrawmempool` with `verbose=true`, now
  return an additional "bip125-replaceable" value indicating whether the
  transaction (or its unconfirmed ancestors) opts-in to asking nodes and
  miners to replace it with a higher-feerate transaction spending any of
  the same inputs.

- The `settxfee` RPC previously silently ignored attempts to set the fee
  below the allowed minimums.  It now prints a warning.  The special
  value of "0" may still be used to request the minimum value.

- The `getaddressinfo` RPC now provides an `ischange` field indicating
  whether the wallet used the address in a change output.

- The `importmulti` RPC has been updated to support P2WSH, P2WPKH,
  P2SH-P2WPKH, and P2SH-P2WSH. Requests for P2WSH and P2SH-P2WSH accept
  an additional `witnessscript` parameter.

- The `importmulti` RPC now returns an additional `warnings` field for
  each request with an array of strings explaining when fields are being
  ignored or are inconsistent, if there are any.

- The `getaddressinfo` RPC now returns an additional `solvable` boolean
  field when Bitcoin Core knows enough about the address's scriptPubKey,
  optional redeemScript, and optional witnessScript in order for the
  wallet to be able to generate an unsigned input spending funds sent to
  that address.

- The `getaddressinfo`, `listunspent`, and `scantxoutset` RPCs now
  return an additional `desc` field that contains an output descriptor
  containing all key paths and signing information for the address
  (except for the private key).  The `desc` field is only returned for
  `getaddressinfo` and `listunspent` when the address is solvable.

- The `importprivkey` RPC will preserve previously-set labels for
  addresses or public keys corresponding to the private key being
  imported.  For example, if you imported a watch-only address with the
  label "cold wallet" in earlier releases of Bitcoin Core, subsequently
  importing the private key would default to resetting the address's
  label to the default empty-string label ("").  In this release, the
  previous label of "cold wallet" will be retained.  If you optionally
  specify any label besides the default when calling `importprivkey`,
  the new label will be applied to the address.

- See the [Mining](#mining) section for changes to `getblocktemplate`.

- The `getmininginfo` RPC now omits `currentblockweight` and `currentblocktx`
  when a block was never assembled via RPC on this node.

- The `getrawtransaction` RPC & REST endpoints no longer check the
  unspent UTXO set for a transaction. The remaining behaviors are as
  follows: 1. If a blockhash is provided, check the corresponding block.
  2. If no blockhash is provided, check the mempool. 3. If no blockhash
  is provided but txindex is enabled, also check txindex.

- The `unloadwallet` RPC is now synchronous, meaning it will not return
  until the wallet is fully unloaded.

REST changes
------------

- A new `/rest/blockhashbyheight/` endpoint is added for fetching the
  hash of the block in the current best blockchain based on its height
  (how many blocks it is after the Genesis Block).

Graphical User Interface (GUI)
------------------------------

- A new Window menu is added alongside the existing File, Settings, and
  Help menus.  Several items from the other menus that opened new
  windows have been moved to this new Window menu.

- In the Send tab, the checkbox for "pay only the required fee"
  has been removed.  Instead, the user can simply decrease the value in
  the Custom Feerate field all the way down to the node's configured
  minimum relay fee.

- In the Overview tab, the watch-only balance will be the only
  balance shown if the wallet was created using the `createwallet` RPC
  and the `disable_private_keys` parameter was set to true.

- The launch-on-startup option is no longer available on macOS if
  compiled with macosx min version greater than 10.11 (use
  CXXFLAGS="-mmacosx-version-min=10.11"
  CFLAGS="-mmacosx-version-min=10.11" for setting the deployment
  sdk version)

Tools
----

- A new `bitcoin-wallet` tool is now distributed alongside Bitcoin
  Core's other executables.  Without needing to use any RPCs, this tool
  can currently create a new wallet file or display some basic
  information about an existing wallet, such as whether the wallet is
  encrypted, whether it uses an HD seed, how many transactions it
  contains, and how many address book entries it has.

Low-level changes
=================

RPC
---

- The `submitblock` RPC previously returned the reason a rejected block
  was invalid the first time it processed that block but returned a
  generic "duplicate" rejection message on subsequent occasions it
  processed the same block.  It now always returns the fundamental
  reason for rejecting an invalid block and only returns "duplicate" for
  valid blocks it has already accepted.

- A new `submitheader` RPC allows submitting block headers independently
  from their block.  This is likely only useful for testing.

Configuration
-------------

- The `-usehd` configuration option was removed in version 0.16. From
  that version onwards, all new wallets created are hierarchical
  deterministic wallets. This release makes specifying `-usehd` an
  invalid configuration option.

Network
-------

- This release allows peers that your node automatically disconnected
  for misbehavior (e.g. sending invalid data) to reconnect to your node
  if you have unused incoming connection slots.  If your slots fill up,
  a misbehaving node will be disconnected to make room for nodes without
  a history of problems (unless the misbehaving node helps your node in
  some other way, such as by connecting to a part of the Internet from
  which you don't have many other peers).  Previously, Bitcoin Core
  banned the IP addresses of misbehaving peers for a period of time
  (default of 1 day); this was easily circumvented by attackers with
  multiple IP addresses.  If you manually ban a peer, such as by using
  the `setban` RPC, all connections from that peer will still be
  rejected.

Security
--------

- This release changes the Random Number Generator (RNG) used from
  OpenSSL to Bitcoin Core's own implementation, although entropy
  gathered by Bitcoin Core is fed out to OpenSSL and then read back in
  when the program needs strong randomness.  This moves Bitcoin Core a
  little closer to no longer needing to depend on OpenSSL, a dependency
  that has caused security issues in the past.

Changes for particular platforms
--------------------------------

- On macOS, Bitcoin Core now opts out of application CPU throttling
  ("app nap") during initial blockchain download, when catching up from
  over 100 blocks behind the current chain tip, or when reindexing chain
  data.  This helps prevent these operations from taking an excessively
  long time because the operating system is attempting to conserve
  power.

Credits
=======

Thanks to everyone who directly contributed to this release:


As well as everyone that helped translating on [Transifex](https://www.transifex.com/projects/p/bagicoin/).
