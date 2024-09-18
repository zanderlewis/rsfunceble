# rsfunceble
[![Crates.io Total Downloads](https://img.shields.io/crates/d/rsfunceble?style=flat&logo=rust&label=Downloads&color=%23000000)](https://crates.io/crates/rsfunceble)

PyFunceble in Rust with concurrency and speed in mind.

When running `rsfunceble -i <filename> -o <filename> -c 100000 -v`, it speeds up the process of ~30,000 URLs and domains on a Github Actions runner from possibly 1+ hours to ~23 minutes.

## Installation
```bash
cargo install rsfunceble
```

## Usage
```bash
rsfunceble -h
```

## License
rsfunceble is distributed under the [MIT](https://opensource.org/licenses/MIT) license.
```
