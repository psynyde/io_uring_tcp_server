cc := "clang"

# cflags := "-Iinclude -Wall -Wextra -pedantic -g -O0 -fno-omit-frame-pointer -std=c99"

cflags := "-Iinclude -Wall -Wextra -pedantic --std=c99 \
    -fsanitize=address \
    -fsanitize=undefined \
    -Wformat=2 \
    -Wformat-security \
    -Wnull-dereference \
    -Wstack-protector \
    -Walloca \
    -Wvla \
    -Warray-bounds \
    -Wimplicit-fallthrough \
    -Wshift-overflow \
    -Wcast-qual \
    -Wconversion \
    -Wcast-align \
    -Wthread-safety \
    -Wthread-safety-beta \
    -Wcomma \
    -Wconditional-uninitialized \
    -Wloop-analysis \
    -Wshift-sign-overflow \
    -Wshorten-64-to-32 \
    -Wtautological-compare \
    -Wunreachable-code-aggressive \
    -Wdocumentation \
    -Wover-aligned \
    -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    -fstack-clash-protection \
    -fPIE \
    -fcf-protection=full \
    -fno-delete-null-pointer-checks \
    -fno-strict-overflow \
    -fno-omit-frame-pointer \
    -O3 \
    -pipe"
libflags := "$(pkg-config --cflags --libs liburing) -lc"
src_dir := "src"
build_dir := "build"

default:
    @ just build

build:
    @ mkdir -p {{ build_dir }}
    @ {{ cc }} {{ cflags }} `find {{ src_dir }} -name '*.c'` -o {{ build_dir }}/server {{ libflags }}

run: build
    ./{{ build_dir }}/server

clean:
    rm -rf {{ build_dir }}
