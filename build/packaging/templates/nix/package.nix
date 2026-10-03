{ lib, stdenvNoCC, fetchurl, makeWrapper, buildFHSEnv, writeShellScript }:
let
  release = builtins.fromJSON (builtins.readFile ./release.json);
  targets = {
    x86_64-linux = "linux_amd64";
    aarch64-linux = "linux_arm64";
    x86_64-darwin = "darwin_amd64";
    aarch64-darwin = "darwin_arm64";
  };
  asset = release.assets.${targets.${stdenvNoCC.hostPlatform.system}};
  raw = stdenvNoCC.mkDerivation {
    pname = "vigolium-unwrapped";
    inherit (release) version;
    src = fetchurl { inherit (asset) url hash; };
    sourceRoot = ".";
    dontConfigure = true;
    dontBuild = true;
    # The release contains embedded executables; preserve the upstream bytes.
    dontFixup = true;
    installPhase = ''
      install -Dm755 vigolium $out/bin/vigolium
      echo nix > $out/bin/.vigolium-package-manager
      install -Dm644 ${./LICENSE} $out/share/licenses/vigolium/LICENSE
      install -Dm644 ${./THIRD_PARTY_NOTICES.md} $out/share/doc/vigolium/THIRD_PARTY_NOTICES.md
    '';
  };
  meta = {
    description = "Web vulnerability scanner and traffic analysis CLI";
    homepage = "https://vigolium.com";
    license = lib.licenses.mit;
    platforms = builtins.attrNames targets;
    mainProgram = "vigolium";
  };
in
if stdenvNoCC.hostPlatform.isLinux then
  # Helpers are extracted at runtime, so autoPatchelfHook on the outer Go
  # executable cannot fix their ELF interpreters. Supply the FHS paths instead.
  buildFHSEnv {
    name = "vigolium";
    inherit (release) version;
    targetPkgs = pkgs: with pkgs; [ glibc stdenv.cc.cc.lib zlib cacert bash coreutils git ];
    runScript = writeShellScript "vigolium-launch" ''
      export VIGOLIUM_PACKAGE_MANAGER=nix
      export VIGOLIUM_DISABLE_UPDATE_CHECK=1
      exec ${raw}/bin/vigolium "$@"
    '';
    inherit meta;
  }
else
  stdenvNoCC.mkDerivation {
    pname = "vigolium";
    inherit (release) version;
    dontUnpack = true;
    nativeBuildInputs = [ makeWrapper ];
    installPhase = ''
      mkdir -p $out/bin
      makeWrapper ${raw}/bin/vigolium $out/bin/vigolium \
        --set VIGOLIUM_PACKAGE_MANAGER nix \
        --set VIGOLIUM_DISABLE_UPDATE_CHECK 1
      ln -s ${raw}/share $out/share
    '';
    inherit meta;
  }
