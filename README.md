[![Crates.io](https://img.shields.io/crates/v/rust-clacc.svg)](https://crates.io/crates/rust-clacc)
[![Build Status](https://github.com/johnoliverdriscoll/rust-clacc/actions/workflows/rust.yml/badge.svg)](https://github.com/johnoliverdriscoll/rust-clacc/actions/workflows/rust.yml)
[![Docs.rs](https://img.shields.io/badge/docs.rs-rustdoc-green)](https://docs.rs/rust-clacc)

# rust-clacc

This is a Rust implementanion of a CL universal accumulator as described
in [Efficient oblivious transfer with membership verification][1].

An accumulation is a fixed size digest that, along with the witness of an
element's addition, can be used to prove an element is a member of a set.
The drawback to this solution is that any state changes to the
accumulation invalidate the witneses of the other elements in the set,
requiring computational resources to update them.

The benefit of CL accumulators is that they support efficient untrusted
witness updates. The resource intensive task of updating witnesses can be
outsourced to an untrusted party without sacrificing the integrity of the
accumulator.

This project is focused on a use case where a central authority is both
memory- and processing-constrained. The authority controls the private key
and is able to add and delete elements while untrusted workers are able to
recalculate witnesses provided they have access to the previous witnesses,
the current state of the accumulator, and its public key.

[1]: https://journals.sagepub.com/doi/pdf/10.1177/1550147719875645
