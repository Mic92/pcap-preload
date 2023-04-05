with import <nixpkgs> {};
mkShell {
  packages = [
    bashInteractive
    cargo
    rustc
    cargo-watch
    rust-analyzer
    go
    cargo-edit
  ];
}
