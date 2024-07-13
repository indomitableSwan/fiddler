# fiddler
This repository is a playground for learning Rust. It is not meant to be used for anything in practice.

It may develop into a beginner tutorial in writing cryptography in Rust, using Douglas Stinson's "Cryptography, Theory and Practice", as a guiding rail. But for now, it is mostly just a container for my thoughts and learning. Many of the crypto-related comments are tongue-in-cheek, pretending that the implemented cryptosystems _are_ for use in the real world, and attempting to support best practices with respect to security and privacy.

Currently there is a library crate, `classical_crypto`, which implements some historical cryptography, and a binary crate, `demo`, that shows how to use the library and lets you play with the implemented ciphers via a command line application.

# build instructions
To build, run 
`cargo make`.

If you have never used  the `cargo-make` task runner before, see [here](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) for installation instructions.

Note that we do not track _Cargo.lock_ in this repository, so builds are not considered reproducible.

# documentation

Documentation of the workspace members is built automatically by `cargo make`. After building, you can open `fiddler/target/doc/fiddler/index.html` in any browser. Alternatively, you can build and open the documentation by running
`
cargo make open_docs
`, which uses the custom flags set in the top-level Makefile.toml file.

Alternatively, run 
`
cargo make open_docs
` from the workspace root, which uses custom flags set in the top-level Makefile.toml file, 
or the standard
`
cargo doc --open
`, which builds and opens the documentation for the included crates as well as their dependencies.

Since this is a learning crate, it may also be helpful to document private items. To do so, pass the option `--document-private-items` to `cargo doc`.

# demo

We have a working demo of the Latin Shift Cipher; this is a very simple command line application that makes use of our public API. To play with the demo, run `cargo run`.