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
            pkgsStatic.buildPackages.liburing

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

            gprof2dot
            (graphviz.override {
              withXorg = false;
            })
            flamegraph

            # perf-tree
            (writeShellScriptBin "perf-tree" ''
              perf script --input=./test/perf.data | gprof2dot -f perf | dot -Gdpi=150 -Tpng -o ./test/perf_tree.png
              if [[ "$1" == "view" ]]; then
                swayimg -f ./test/perf_tree.png
              fi
            '')

            # perf-flame
            (writeShellScriptBin "perf-flame" ''
              perf script --input=./test/perf.data | stackcollapse-perf.pl | flamegraph.pl > ./test/perf_flame.svg
              if [[ "$1" == "view" ]]; then
                zen ./test/perf_flame.svg
              fi
            '')

            (writeShellScriptBin "grind" ''
              TOOL="$1"
              shift || true   # shift args so you can pass extra args to your server
              case "$TOOL" in
                memcheck)
                  valgrind \
                    --log-file=./test/valgrind-memcheck.log \
                    --tool=memcheck \
                    --leak-check=full \
                    --show-leak-kinds=all \
                    --track-origins=yes \
                    --errors-for-leak-kinds=all \
                    ./build/server "$@"
                  ;;

                massif)
                  valgrind \
                    --massif-out-file=./test/valgrind-massif.log \
                    --tool=massif \
                    --time-unit=ms \
                    --detailed-freq=10 \
                    --max-snapshots=200 \
                    ./build/server "$@"
                  echo "Massif output: ms_print massif.out.*"
                  ;;

                callgrind)
                  valgrind \
                    --callgrind-out-file=./test/valgrind-callgrind.log \
                    --tool=callgrind \
                    --dump-instr=yes \
                    --collect-jumps=yes \
                    ./build/server "$@"
                  echo "Callgrind output: callgrind_annotate callgrind.out.*"
                  ;;

                cachegrind)
                  valgrind \
                    --cachegrind-out-file=./test/valgrind-cachegrind.log \
                    --tool=cachegrind \
                    --branch-sim=yes \
                    ./build/server "$@"
                  echo "Cachegrind output: cg_annotate cachegrind.out.*"
                  ;;

                helgrind)
                  valgrind \
                    --log-file=./test/valgrind-helgrind.log \
                    --tool=helgrind \
                    --history-level=full \
                    --track-lockorders=yes \
                    --free-is-write=yes \
                    ./build/server "$@"
                  ;;

                *)
                  echo "Usage: grind {memcheck|massif|callgrind|cachegrind|helgrind} [server-args...]"
                  exit 1
                  ;;
              esac
            '')
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
            just.enable = true;
          };
        };
      }
    );
}
