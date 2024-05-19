# Kernel Launcher

Kernel Launcher is a payload for PS4 kernel to load and run ELF file inside the kernel. The ELF to run must be designed to run within the PS4 kernel. That mean you cannot run other ELFs like Linux ELF etc. It was designed to run ELF produced by Rust for `x86_64-unknown-none` target. Only 11.00 is supported.

## Building from source

### Prerequisites

- Rust on nightly channel

### Install additional Rust component

```sh
rustup component add rust-src llvm-tools
```

### Build

```sh
./build.py
```

## License

MIT
