{
  description = "IO uring server";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        project = "IO_uring server";
      in
      {
        devShells.default = pkgs.mkShell {
          name = project;
          LSP_SERVER = "clangd";
          packages = with pkgs; [
            liburing

            pkg-config
            just
            bear
            radamsa

            gdb
            valgrind
            linuxPackages_latest.perf

            llvmPackages_latest.lldb
            llvmPackages_latest.libllvm
            llvmPackages_latest.libcxx
            llvmPackages_latest.clang
            llvmPackages_latest.clang-tools
          ];

          shellHook = ''
            export PATH="${pkgs.llvmPackages_latest.clang-tools}/bin:$PATH"
            echo -e '(¬_¬") Entered ${project}'
          '';
          env = {
            CLANGD_PATH = "${pkgs.llvmPackages_latest.clang-tools}/bin/clangd";
          };
        };
        formatter = treefmt-nix.lib.mkWrapper pkgs {
          projectRootFile = "flake.nix";
          programs = {
            nixfmt.enable = true;
            clang-format.enable = true;
          };
        };
      }
    );
}
