#![feature(stdsimd, test)]

extern crate byteorder;
#[allow(unused_imports)]
#[macro_use]
extern crate crunchy;
extern crate crypto;
extern crate hex;
extern crate packed_simd;

pub mod sha256;
