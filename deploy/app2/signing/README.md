# Release signing keys

Do not commit release-signing private keys to this repository.

The previous `sentinel-signing.key` value was committed to Git history and must be treated as compromised. Rotate the release-signing key before requiring signed installs again:

1. Generate a new Ed25519 signing key on an offline administrator workstation or inside a managed KMS/HSM.
2. Store the private key outside the repository with restricted operator access and backup controls.
3. Publish only the new public key or bake it into the deployment artifact that serves `install-agent.sh`.
4. Re-sign every downloadable `sentinel-agent-*` binary and publish matching `.sha256` and `.sig` files.
5. Remove any binaries signed by the compromised key from the download host.

Local private-key filenames such as `*.key`, `*.pem`, `*.p8`, and `*.p12` are ignored by `.gitignore` as a last-resort guard. Treat `.gitignore` as defense-in-depth only; signing material should live outside the checkout.
