#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(alloc_error_handler)]
#![feature(asm)]

extern crate alloc;
extern crate bootloader;
extern crate lazy_static;
extern crate rlibc;
extern crate x86_64;
#[macro_use]
extern crate libvmm;

mod io;
mod heap;
mod vm;
mod pic;
mod vmm;
#[macro_use]
mod output;
mod emulator;
mod kernel;
mod page_alloc;
mod interrupt_controller;

use crate::kernel::*;
use crate::vmm::run_guest;
use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
}

#[test_case]
fn simple_register_access() {
    assert_eq!(run_guest(), true);
}

pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("[START]");
    for test in tests {
        test();
    }
    println!("[END  ]");
    exit_qemu(QemuExitCode::Success);
}

#[cfg(test)]
entry_point!(kernel_main);
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    kernel_init(boot_info);

    #[cfg(test)]
    test_main();

    exit_qemu(QemuExitCode::Success);
    loop {}
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[FAIL ]\n");
    println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    loop {}
}
