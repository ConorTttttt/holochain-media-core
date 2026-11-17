# Contributing and review gates

This project is pre-release and has no final software licence decision. Do not publish or distribute packages yet.

1. Work in short feature branches and open draft PRs for cross-application or security-sensitive changes.
2. Run cargo fmt --all -- --check, cargo clippy --workspace --all-targets -- -D warnings, and cargo test --workspace --all-targets.
3. For changed cryptographic formats, add independent golden vectors from Music's existing implementation and wrong-signer/tamper/version tests. Never rewrite existing user data implicitly.
4. Never commit real content keys, private grants, Holochain signing credentials, host private keys, user tokens or production media.
5. Keep Holochain, MoQ and application-specific UI/codecs separated as in docs/architecture.md.
6. Record which tests were run locally, which passed in CI, and what remains untested on physical devices.
7. Require explicit review before moving from draft to production or merging breaking changes into dependent applications.

Commit messages should explain the behaviour change and security boundary. A signed review entry, encrypted package and receipt are not proof of copyright, payment or permanent availability.
