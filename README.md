# binja-msp430

A Binary Ninja plugin to add support for the MSP430 family of microcontrollers

## Use

Simply install the plugin to your Binary Ninja and select the correct architecture when opening an image.

## Compilation

Currently there are no official releases of this so you'll have to build it yourself to install. This is fairly straight forward though you will need a functioning Rust development environment. You can follow the instructions [here](https://rustup.rs/) to set that up.

**NOTE:** Exact MSRV is unknown but it should work on any version that support edition 2021.

With a valid Rust environment functioning and the repository cloned you can run `cargo build --release` from within the repository and it should build the library.

## Installation

Copy `target/release/libbinja_msp430.{dylib,dll,so}` from the releases directory into your Binary Ninja plugins directory then restart Binary Ninja. You should see a log message that it has been loaded.

## It's not working

If you see an error message `This plugin was built for an outdated core ABI` the version of the Binary Ninja api that the plugin is built against is older than your version of Binary Ninja. It needs to be updated. You can do this by first running `cargo update` then rebuilding and re-installing. Pinned versions on branches will eventially be setup on branches for stable releases but it isn't done yet.

## License

This project is licensed under the terms of the [MIT](LICENSE) open source license
