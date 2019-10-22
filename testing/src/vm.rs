use x86_64::structures::paging::PhysFrame;

pub struct VM;

static mut PHYS_OFFSET: Option<u64> = None;
static mut ROOT: Option<PhysFrame> = None;

impl VM {
    pub fn phys_offset() -> u64 {
        unsafe { PHYS_OFFSET.unwrap() }
    }

    pub fn set_phys_offset(offset: u64) {
        unsafe { PHYS_OFFSET.replace(offset); }
    }

    pub fn phys_to_virt(phys: u64) -> u64 {
        phys + VM::phys_offset()
    }

    pub fn virt_to_phys(virt: u64) -> u64 {
        virt - VM::phys_offset()
    }

    pub fn root_mm() -> PhysFrame {
        unsafe { ROOT.unwrap() }
    }
}