#![feature(stdsimd, test)]

extern crate byteorder;
#[allow(unused_imports)]
#[macro_use]
extern crate crunchy;
extern crate hex;
extern crate packed_simd;
extern crate sha2;

pub mod sha256;
