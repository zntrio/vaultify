{ pkgs ? import <nixpkgs> { } }:

with pkgs;

mkShell {
  buildInputs = [
    go_1_18
    golangci-lint
    vault
  ];
}
