# Installs the released cw and nothing else (docs/dev/CLI-NIX-INSTALL.md).
# nix/release.json names the release and each system's executable by digest;
# a release rewrites only that file.
{
  description = "cw, the Codewire command line, from its signed releases";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { nixpkgs, ... }:
    let
      inherit (nixpkgs) lib;
      release = builtins.fromJSON (builtins.readFile ./nix/release.json);
      # The release target each Nix system installs. A pin for another target
      # is refused rather than installed.
      targets = {
        x86_64-linux = "x86_64-unknown-linux-musl";
        aarch64-linux = "aarch64-unknown-linux-gnu";
        x86_64-darwin = "x86_64-apple-darwin";
        aarch64-darwin = "aarch64-apple-darwin";
      };
      forSystems = f: lib.genAttrs (builtins.attrNames targets) f;

      cw =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pin = release.targets.${system};
          # Only the arm64 Linux release is linked to glibc; its interpreter is
          # /lib/ld-linux-aarch64.so.1, which NixOS doesn't have.
          glibcLinked = pin.target == "aarch64-unknown-linux-gnu";
        in
        assert lib.assertMsg (
          release.schema == "codewire.cw.nix/v1"
        ) "nix/release.json: unknown schema ${release.schema}";
        assert lib.assertMsg (
          pin.target == targets.${system}
        ) "nix/release.json: ${system} pins ${pin.target}, not ${targets.${system}}";
        pkgs.stdenvNoCC.mkDerivation {
          pname = "cw";
          version = lib.removePrefix "v" release.release_tag;
          src = pkgs.fetchurl {
            name = "cw-${release.release_tag}-${pin.target}";
            url = "https://releases.codewire.sh/cw/v1/blobs/sha256/${pin.sha256}";
            inherit (pin) sha256;
          };
          dontUnpack = true;
          dontConfigure = true;
          dontBuild = true;
          # No strip and no patch: a changed macOS executable loses its
          # Developer ID signature, and the others run as released.
          dontFixup = true;
          nativeBuildInputs = lib.optional glibcLinked pkgs.patchelf;
          installPhase = ''
            runHook preInstall
            install -D -m 0755 "$src" "$out/bin/cw"
          ''
          + lib.optionalString glibcLinked ''
            patchelf \
              --set-interpreter ${pkgs.glibc}/lib/ld-linux-aarch64.so.1 \
              --set-rpath ${pkgs.glibc}/lib \
              "$out/bin/cw"
          ''
          + ''
            chmod 0555 "$out/bin/cw"
            runHook postInstall
          '';
          meta = {
            description = "Codewire's command line: sandboxes and local VMs for coding agents";
            homepage = "https://codewire.sh";
            license = lib.licenses.agpl3Only;
            sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
            platforms = [ system ];
            mainProgram = "cw";
          };
        };
    in
    {
      packages = forSystems (
        system:
        let
          package = cw system;
        in
        {
          cw = package;
          default = package;
        }
      );

      apps = forSystems (
        system:
        let
          app = {
            type = "app";
            program = "${cw system}/bin/cw";
            meta.description = "Run cw";
          };
        in
        {
          cw = app;
          default = app;
        }
      );
    };
}
