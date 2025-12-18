{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
        rust-toolchain = pkgs.symlinkJoin {
          name = "rust-toolchain";
          paths = with pkgs; [
            rustc
            cargo
            rustPlatform.rustcSrc
          ];
        };
      in
      {
        packages = {
          quiche-endpoint = pkgs.rustPlatform.buildRustPackage {
            pname = manifest.name;
            version = manifest.version;
            cargoLock.lockFile = ./Cargo.lock;
            src = pkgs.lib.cleanSource ./.;
            nativeBuildInputs = with pkgs; [
              clang
              git
              cmake
            ];
            env = {
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            };
          };
          default = self.packages.${system}.quiche-endpoint;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            clippy
            rustfmt
            rust-analyzer
            rust-toolchain
            cmake
            clang
          ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      }
    );
}
