PGP keys
========

This folder contains the public keys of developers and active contributors.

The keys are mainly used to sign git commits or the build results of Gitian
builds.

You can import the keys into gpg as follows. Also, make sure to fetch the
latest version from the key server to see if any key was revoked in the
meantime.

```sh
gpg --import ./*.pgp
gpg --refresh-keys
```

To fetch keys of Gitian builders and active developers, feed the list of
fingerprints of the primary keys into gpg:

```sh
while read fingerprint keyholder_name; do gpg --keyserver hkp://subset.pool.sks-keyservers.net --recv-keys ${fingerprint}; done < ./keys.txt
```

Add your key to the list if you provided Gitian signatures for two major or
minor releases of Chaincoin Core.
