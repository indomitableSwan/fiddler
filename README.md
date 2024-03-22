# fiddler
This repository is a playground for learning Rust. It is not meant to be used for anything in practice.

It may develop into a beginner tutorial in writing cryptography in Rust, using Douglas Stinson's "Cryptography, Theory and Practice", as a guide. But for now, it is just a container for my thoughts and learning.

# build instructions
To build, run 
`cargo make`.

If you have never used  the `cargo-make` task runner before, see [here](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) for installation instructions.

Note that we do not track _Cargo.lock_ in this repository, so builds are not considered reproducible.

# documentation

Documentation is built automatically by `cargo make`. After building, open `fiddler/target/doc/fiddler/index.html` in any browser. 

Alternatively, run 
`
cargo doc --no-deps --open
` or
`cargo doc --open`, depending on whether or not you want to build docs for dependencies as well as `fiddler`.

Since this is a learning crate, it may also be helpful to document private items. To do so, pass the option `--document-private-items` to `cargo doc`.

# example

We have a working demo of the Latin Shift Cipher; this is a very simple command line application that makes use of our public API.