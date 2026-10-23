# TUF reference repository fixtures

These files are copied from the test repository shipped with AWS Labs' `awslabs/tough`, tag `tough-v0.24.0`, commit `98d8eb8b2ce63515d9b4981c938ef6453c5b5771`.

Upstream fixture directory:
https://github.com/awslabs/tough/tree/tough-v0.24.0/tough/tests/data/tuf-reference-impl

The upstream README identifies this metadata set as a subset of the Python TUF reference implementation's test repository, pinned at:
https://github.com/theupdateframework/tuf/tree/21c3285216d2ded8feed7c57ffdb8d5dc045a246/tests/repository_data/repository

Purpose in Deku: deterministic tests of signed TUF metadata loading and target digest verification. The keys, signatures and target contents are test fixtures only. They must never be used to sign or authenticate a real Deku package repository. Expirations are set to 2030 for this upstream test repository; independent expiry enforcement tests remain necessary.

Upstream licensing and attribution remain applicable. The fixture metadata is test data rather than production configuration.
