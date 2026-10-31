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

Each RuntimeClass also carries Kata runtime-rs `podFixed` accounting. Kubernetes
adds this VM/runtime overhead to workload requests and limits before scheduling
and cgroup enforcement. Omitting it can make a small workload fail before VM
startup even when the node has ample memory.

These values are measured, not copied from upstream's chart defaults: Kata's
sizing guide says `podFixed` must cover guest- and host-side overhead, and that
operators tune it for their own deployment. When a Pod's containers all reach
their limits while writing to disk, its guest RAM is full and only this margin is
left for the VMM, virtiofsd and their host page cache. Below it the host OOM-kills
the VM. Re-measure with `scripts/runtime/dev/prove-dev-runtime-memory-fill.sh`
before changing a value or supporting a larger shape.

`overhead` can change in place, but a Pod keeps the value it was admitted with: a
running sandbox gets the new value at its next start, and unclaimed warm-pool
members within a day, when age replaces them. The warm-pool node cap and the
scheduler use the live value.

Do not add a confidential node selector by node name. Infra owns the host SNP
gate and publishes the scheduling capability label.

See `docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md` for the profile-to-runtime
contract. The Kubernetes RuntimeClass is an implementation detail of the
profile, not the product-level selector.
