{
  description = "Vigolium release binaries";
  # Pin the package set as well as the release downloads. Update deliberately.
  # 26.05 retains Intel macOS support, unlike the 26.11 development branch.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/7fc6f2c20af09cdcaf48b92ec3121860139ec668";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
    in {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          vigolium = pkgs.callPackage ./package.nix { };
        in { inherit vigolium; default = vigolium; });
      apps = eachSystem (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/vigolium";
          meta = self.packages.${system}.default.meta;
        };
      });
    };
}
