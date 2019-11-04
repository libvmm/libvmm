use crate::page_alloc::page_alloc_init;
use crate::vm::VM;
use bootloader::BootInfo;
use lazy_static::lazy_static;
use x86_64::instructions::segmentation::*;
use x86_64::instructions::tables::*;
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::structures::gdt::*;
use x86_64::structures::tss::*;

static TSS: TaskStateSegment = TaskStateSegment::new();

lazy_static! {
    static ref GDT: GlobalDescriptorTable = {
        let mut gdt = GlobalDescriptorTable::new();

        let code = Descriptor::kernel_code_segment();
        let tss = Descriptor::tss_segment(&TSS);

        gdt.add_entry(code);
        gdt.add_entry(tss);
        gdt
    };
}

fn init_segmentation() {
    GDT.load();

    unsafe {
        load_es(SegmentSelector(0));
        load_ss(SegmentSelector(0));
        load_ds(SegmentSelector(0));
        load_fs(SegmentSelector(0));
        load_gs(SegmentSelector(0));
        set_cs(SegmentSelector(0x8));
        load_tss(SegmentSelector(0x10))
    }
}

pub fn kernel_init(boot_info: &'static BootInfo) {
    unsafe {
        Cr0::write_raw(Cr0::read_raw() | Cr0Flags::NUMERIC_ERROR.bits());
    }

    VM::set_phys_offset(boot_info.physical_memory_offset);
    page_alloc_init(boot_info);
    init_segmentation();
}
