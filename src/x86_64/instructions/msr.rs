#[derive(Copy, Clone)]
pub enum MSR {
    IA32_APIC_BASE = 0x1b,
    IA32_FEATURE_CONTROL = 0x3a,

    IA32_SYSENTER_CS = 0x174,
    IA32_SYSENTER_ESP = 0x175,
    IA32_SYSENTER_EIP = 0x176,

    IA32_DEBUGCTLMSR = 0x1d9,
    IA32_CR_PAT = 0x277,

    IA32_VMX_BASIC = 0x480,
    IA32_VMX_PINBASED_CTLS = 0x481,
    IA32_VMX_PROCBASED_CTLS = 0x482,
    IA32_VMX_EXIT_CTLS = 0x483,
    IA32_VMX_ENTRY_CTLS = 0x484,
    IA32_VMX_PROCBASED_CTLS2 = 0x48b,
    IA32_VMX_TRUE_PINBASED_CTLS = 0x48d,
    IA32_VMX_TRUE_PROCBASED_CTLS = 0x48e,
    IA32_VMX_TRUE_EXIT_CTLS = 0x48f,
    IA32_VMX_TRUE_ENTRY_CTLS = 0x490,

    IA32_TSC_DEADLINE = 0x6e0,

    GS_BASE = 0xc0000101,
    FS_BASE = 0xc0000100,
}

impl MSR {
    pub unsafe fn read(&self) -> u64 {
        let low: u32;
        let high: u32;

        llvm_asm!("rdmsr" : "={eax}" (low), "={edx}" (high) : "{ecx}" (*self) : "memory" : "volatile");
        ((high as u64) << 32) | (low as u64)
    }

    pub unsafe fn write(&self, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;

        llvm_asm!("wrmsr" :: "{ecx}" (*self), "{eax}" (low), "{edx}" (high) : "memory" : "volatile" );
    }
}
