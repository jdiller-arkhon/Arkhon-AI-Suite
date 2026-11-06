# arkhon-keygen

Offline key tooling for the key hierarchy in brief §6 and ADR-0007. **Run `root` on an offline
machine. Never commit or upload any `.key` file.**

```bash
arkhon-keygen root    --out root.key                         # prints the root PUBLIC key to embed in the runtime
arkhon-keygen issuing --root root.key --out issuing.key --cert issuing.cert --serial 1 --days 365
arkhon-keygen revoke  --root root.key --version 2 --serials 1,4 --out revocations.bin
```

- Key files are created new (an existing file is never overwritten) with owner-only (0600) permissions.
- Each file holds the 32-byte Ed25519 seed as one line of hex.
- The issuing key goes into the License Manager's secret store or KMS, never into the repo.
