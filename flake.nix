{
  description = "tiber devShell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.rustup
              pkgs.stdenv.cc
              pkgs.clang
              pkgs.llvm
              pkgs.wasm-pack
              pkgs.binaryen
              pkgs.cargo-fuzz
              pkgs.cargo-llvm-cov
              pkgs.expect
              pkgs.python3
            ];

            shellHook = ''
              export RUSTUP_HOME="$PWD/.nix-rust/rustup"
              export CARGO_HOME="$PWD/.nix-rust/cargo"
              export PATH="$CARGO_HOME/bin:$PATH"
              rustup toolchain install stable \
                --profile default \
                --component rustfmt \
                --component clippy \
                --component llvm-tools-preview \
                >/dev/null
              rustup target add wasm32-unknown-unknown --toolchain stable >/dev/null
              rustup toolchain install nightly --profile minimal >/dev/null
              rustup default stable >/dev/null
            '';
          };
        });
    };
}
