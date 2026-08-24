# Runtime profile base

This base owns the Kubernetes-facing RuntimeClass contract for Codewire runtime
profiles.
It does not install Kata Containers, Cloud Hypervisor, Trustee, CoCo
guest-components, containerd handlers, or node packages. Those host/runtime
pieces are owned by the infra repo.

Managed Codewire sandboxes should use an approved runtime profile. `runc` remains a
diagnostic/bootstrap compatibility path and is refused by managed creation
unless `SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME=true` is set. This base adds the
defense-in-depth runtime classes used by the Codewire Guard umbrella:

- `commodity`: commodity KVM nodes running Kata + Cloud Hypervisor through
  the `kata-clh` CRI handler. This is VM isolation and defense in depth, not
  CoCo/SNP-grade cryptographic host-root protection.
- `confidential`: SNP-capable KVM nodes running Kata + QEMU-SNP through the
  `kata-qemu-snp` CRI handler. This class is for the confidential runtime proof
  path and schedules only onto nodes labelled
  `node.codewire.sh/confidential-snp=true`.

Each RuntimeClass also carries the matching Kata runtime-rs `podFixed`
accounting. Kubernetes adds this VM/runtime overhead to workload requests and
limits before scheduling and cgroup enforcement. Keep these values aligned
with the corresponding upstream Kata shim defaults; omitting them can make a
small workload fail before VM startup even when the node has ample memory.

Do not add a confidential node selector by node name. Infra owns the host SNP
gate and publishes the scheduling capability label.

See `docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md` for the profile-to-runtime
contract. The Kubernetes RuntimeClass is an implementation detail of the
profile, not the product-level selector.
