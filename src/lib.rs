#![no_std]
#![feature(asm)]
#![feature(global_asm)]

#[cfg(target_arch = "x86_64")]
extern crate libvmm_macros;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

pub const SHIFT_4K: u8 = 12;
pub const SHIFT_2M: u8 = 21;
pub const SHIFT_1G: u8 = 30;
pub const SHIFT_512G: u8 = 39;

pub const KiB: usize = 1024;
pub const MiB: usize = 0x100000;
const GiB: usize = 0x40000000;

pub const PAGE_4K: usize = 4 * KiB;
pub const PAGE_2M: usize = 2 * MiB;
pub const PAGE_1G: usize = 1 * GiB;

trait AlignedAddress {
    fn aligned(&self, shift: u8) -> bool;
}

impl AlignedAddress for u64 {
    fn aligned(&self, shift: u8) -> bool {
        return ((*self) & ((1 << shift) - 1)) == 0;
    }
}

#[macro_export]
macro_rules! unsafe_cast {
    ($x:expr => $t:ty) => {
        unsafe {
            use core::mem::transmute;
            transmute::<_, $t>($x)
        }
    };
}
