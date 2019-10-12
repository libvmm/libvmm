use bitflags::bitflags;

bitflags! {
    pub struct VMEntryControls: u32 {
        const LOAD_DEBUG_CONTROLS           = 1 << 2;
        const IA32E_MODE_GUEST              = 1 << 9;
        const ENTRY_TO_SMM                  = 1 << 10;
        const DEACTIVATE_DUAL_MONITOR       = 1 << 11;
        const LOAD_PERF_GLOBAL_CONTROL      = 1 << 13;
        const LOAD_PAT                      = 1 << 14;
        const LOAD_EFER                     = 1 << 15;
        const LOAD_BND_CFGS                 = 1 << 16;
        const CONCEAL_VMX_FROM_PT           = 1 << 17;
    }
}

bitflags! {
    pub struct VMExitControls: u32 {
        const SAVE_DEBUG_CONTROLS           = 1 << 2;
        const IA32E_MODE_GUEST              = 1 << 9;
        const LOAD_PERF_GLOBAL_CONTROL      = 1 << 12;
        const ACK_INTERRUPT_ON_EXIT         = 1 << 15;
        const SAVE_PAT                      = 1 << 18;
        const LOAD_PAT                      = 1 << 19;
        const SAVE_EFER                     = 1 << 20;
        const LOAD_EFER                     = 1 << 21;
        const SAVE_VMX_PREEMPTION_TIMER     = 1 << 22;
        const CLEAR_BND_CFGS                = 1 << 23;
        const CONCEAL_VMX_FROM_PT           = 1 << 24;
    }
}

bitflags! {
    pub struct PinVMExecControl: u32 {
        const EXTERNAL_INTERRUPT_EXIT       = 1 << 0;
        const NMI_EXITING                   = 1 << 3;
        const VIRTUAL_NMIS                  = 1 << 5;
        const VMX_PREEMPTION_TIMER          = 1 << 6;
        const POSTED_INTERRUPTS             = 1 << 7;
    }
}

bitflags! {
    pub struct PrimaryVMExecControl: u32 {
        const INTERRUPT_WINDOW_EXITING  = 1 << 2;
        const USE_TSC_OFFSETTING        = 1 << 3;
        const HLT_EXITING               = 1 << 7;
        const INVLPG_EXITING            = 1 << 9;
        const MWAIT_EXITING             = 1 << 10;
        const RDPMC_EXITING             = 1 << 11;
        const RDTSC_EXITING             = 1 << 12;
        const CR3_LOAD_EXITING          = 1 << 15;
        const CR3_STORE_EXITING         = 1 << 16;
        const CR8_LOAD_EXITING          = 1 << 19;
        const CR8_STORE_EXITING         = 1 << 20;
        const USE_TPR_SHADOW            = 1 << 21;
        const NMI_WINDOW_EXITING        = 1 << 22;
        const MOVDR_EXITING             = 1 << 23;
        const UNCONDITIONAL_IO_EXITING  = 1 << 24;
        const USE_IO_BITMAPS            = 1 << 25;
        const MONITOR_TRAP_FLAG         = 1 << 27;
        const USE_MSR_BITMAP            = 1 << 28;
        const MONITOR_EXITING           = 1 << 29;
        const PAUSE_EXITING             = 1 << 30;
        const SECONDARY_CONTROLS        = 1 << 31;
    }
}

bitflags! {
    pub struct SecondaryVMExecControl: u32 {
        const VIRTUALIZE_APIC_ACCESSES      = 1 << 0;
        const EPT                           = 1 << 1;
        const DESCRIPTOR_TABLE_SETTING      = 1 << 2;
        const RDTSCP                        = 1 << 3;
        const VIRTUALIZE_X2APIC_MODE        = 1 << 4;
        const VPID                          = 1 << 5;
        const WBINVD_EXITING                = 1 << 6;
        const UNRESTRICTED_GUEST            = 1 << 7;
        const APIC_REGISTER_VIRTUALIZATION  = 1 << 8;
        const VIRTUAL_INTERRUPT_DELIVERY    = 1 << 9;
        const PAUSE_LOOP_EXITING            = 1 << 10;
        const RDRAND_EXITING                = 1 << 11;
        const INVPCID                       = 1 << 12;
        const VM_FUNCTIONS                  = 1 << 13;
        const VMCS_SHADOWING                = 1 << 14;
        const ENCLS_EXITING                 = 1 << 15;
        const RDSEED_EXITING                = 1 << 16;
        const PML                           = 1 << 17;
        const EPT_VIOLATION_VE              = 1 << 18;
        const CONCEAL_VMX_FROM_PT           = 1 << 19;
        const XSAVESXRSTORS                 = 1 << 20;
        const EXECUTE_CONTROL_EPT           = 1 << 22;
        const TSC_SCALING                   = 1 << 25;
    }
}

bitflags! {
    pub struct ExceptionBitmap: u32 {
        const DIVIDE_BY_ZERO            = 1 << 0;
        const DEBUG                     = 1 << 1;
        const NMI                       = 1 << 2;
        const BREAKPOINT                = 1 << 3;
        const OVERFLOW                  = 1 << 4;
        const BOUNDARY_RANGE_EXCEEDED   = 1 << 5;
        const INVALID_OP_CODE           = 1 << 6;
        const DEVICE_NOT_AVAILABLE      = 1 << 7;
        const DOUBLE_FAULT              = 1 << 8;
        const INVALID_TSS               = 1 << 10;
        const SEGMENT_NOT_PRESENT       = 1 << 11;
        const STACK_SEGMENT_FAULT       = 1 << 12;
        const GENERAL_PROTECTION_FAULT  = 1 << 13;
        const PAGE_FAULT                = 1 << 14;
        const X87_FLOATING_POINT        = 1 << 16;
        const ALIGNMENT_CHECK           = 1 << 17;
        const MACHINE_CHECK             = 1 << 18;
        const SIMD_FLOATING_POINT       = 1 << 19;
        const VIRTUALIZATION            = 1 << 20;
        const SECURITY_EXCEPTION        = 1 << 30;
    }
}
