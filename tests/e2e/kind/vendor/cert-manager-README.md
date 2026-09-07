# cert-manager Kind fixture

Generated from the official cert-manager **v1.17.1** Helm chart, matching the
Dev controller version under test. This is a disposable-cluster test dependency,
not a Dev controller upgrade or application deployment.

- Chart: `oci://quay.io/jetstack/charts/cert-manager:v1.17.1`
- OCI digest: `sha256:be0fbcfc39960d0393d6cad446fce654f3e6a8ee5a44bc7d601dda6813f230e0`
- Archive SHA-256: `48707f6e8937290da96065dc7de8b4f5a95d9707798d4b5a0d560f78c12996f7`
- Verified Helm provenance signer:
  `1020CF3C033D4F35BAE1C19E1226061C665DF13E`
  (cert-manager Maintainers).
- Public keyring SHA-256:
  `3c150100c94f127dc92acbc5d71dc6417cd87b726fc542ea5e15e8f98653284c`.
- Rendered YAML SHA-256:
  `c8d451522fbf7db1a4c11d2d8c4c0253f51f4b54fd4396b467c0a582fe834615`.

Render with Helm v3.16.4:
`helm template cert-manager cert-manager-v1.17.1.tgz --namespace cert-manager
--values tests/e2e/kind/cert-manager-values.yaml --output-dir RENDER_DIR`.
In `RENDER_DIR/cert-manager/templates`, run `kustomize create --autodetect`,
then Kustomize v5.4.3 `build --output cert-manager-v1.17.1.yaml`.
Retain the file's three-line Codewire customization notice above the render.
Keep the entire CRD/controller/webhook render together.

The three linux/amd64 upstream image digests are pinned in the Kind support
image loader. Only verified, side-loaded local aliases appear in this manifest.
The fixture enables Certificate owner references, uses independent test CA
domains, and tests actual issuance instead of Helm's extra startup-check Job.
Ingress-shim is excluded so it does not manage the existing ingress TLS fixture.

Upstream is Apache-2.0; see `cert-manager-LICENSE`.
The public signing key is published by the
[cert-manager project](https://cert-manager.io/public-keys/cert-manager-keyring-2021-09-20-1020CF3C033D4F35BAE1C19E1226061C665DF13E.gpg).
