use crate::{AlignedAddress, SHIFT_4K};

pub mod msr;
pub mod vmcs;
pub mod vmcs_validator;

pub struct VMX;

impl VMX {
    pub unsafe fn vmxon(address: u64) -> bool {
        if !address.aligned(SHIFT_4K) {
            return false;
        }

        asm!("vmxon $0":: "m" (address));
        true
    }

    pub unsafe fn vmxoff() {
        asm!("vmxoff");
    }

    pub unsafe fn vmcall() {}

    pub unsafe fn vmfunc() {}
}
