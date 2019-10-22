use bitflags::bitflags;
use libvmm_macros::*;
use crate::{AlignedAddress, SHIFT_4K};
use crate::x86_64::instructions::msr::*;
use crate::x86_64::structures::guest::VcpuGuestRegs;

global_asm!(include_str!("vmx.s"));

extern "C" {
    fn vmx_return() -> bool;
    fn vmx_vmlaunch(guest_regs: &mut VcpuGuestRegs) -> bool;
    fn vmx_vmresume(guest_regs: &mut VcpuGuestRegs) -> bool;
}

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

#[derive(Debug, Copy, Clone)]
pub enum VMXExitReason {
    EXCEPTION_NMI           = 0,
    EXTERNAL_INTERRUPT      = 1,
    TRIPLE_FAULT            = 2,
    PENDING_INTERRUPT       = 7,
    NMI_WINDOW              = 8,
    TASK_SWITCH             = 9,
    CPUID                   = 10,
    HLT                     = 12,
    INVD                    = 13,
    INVLPG                  = 14,
    RDPMC                   = 15,
    RDTSC                   = 16,
    VMCALL                  = 18,
    VMCLEAR                 = 19,
    VMLAUNCH                = 20,
    VMPTRLD                 = 21,
    VMPTRST                 = 22,
    VMREAD                  = 23,
    VMRESUME                = 24,
    VMWRITE                 = 25,
    VMOFF                   = 26,
    VMON                    = 27,
    CR_ACCESS               = 28,
    DR_ACCESS               = 29,
    IO_INSTRUCTION          = 30,
    MSR_READ                = 31,
    MSR_WRITE               = 32,
    INVALID_STATE           = 33,
    MSR_LOAD_FAIL           = 34,
    MWAIT_INSTRUCTION       = 36,
    MONITOR_TRAP_FLAG       = 37,
    MONITOR_INSTRUCTION     = 39,
    PAUSE_INSTRUCTION       = 40,
    MCE_DURING_VMENTRY      = 41,
    TPR_BELOW_THRESHOLD     = 43,
    APIC_ACCESS             = 44,
    EOI_INDUCED             = 45,
    GDTR_IDTR               = 46,
    LDTR_TR                 = 47,
    EPT_VIOLATION           = 48,
    EPT_MISCONFIG           = 49,
    INVEPT                  = 50,
    RDTSCP                  = 51,
    PREEMPTION_TIMER        = 52,
    INVVPID                 = 53,
    WBINVD                  = 54,
    XSETBV                  = 55,
    APIC_WRITE              = 56,
    RDRAND                  = 57,
    INVPCID                 = 58,
    VMFUNC                  = 59,
    ENCLS                   = 60,
    RDSEED                  = 61,
    PML_FULL                = 62,
    XSAVES                  = 63,
    XRSTORS                 = 64,
}

#[vmcs_access(16, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField16Control {
    VIRTUAL_PROCESSOR_ID    = 0x00000000,
    POSTED_INTR_NV          = 0x00000002,
    EPTP_INDEX              = 0x00000004,
}

#[vmcs_access(16, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField16Guest {
    ES_SELECTOR     = 0x00000800,
    CS_SELECTOR     = 0x00000802,
    SS_SELECTOR     = 0x00000804,
    DS_SELECTOR     = 0x00000806,
    FS_SELECTOR     = 0x00000808,
    GS_SELECTOR     = 0x0000080a,
    LDTR_SELECTOR   = 0x0000080c,
    TR_SELECTOR     = 0x0000080e,
    INTR_STATUS     = 0x00000810,
    PML_INDEX       = 0x00000812,
}

#[vmcs_access(16, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField16Host {
    ES_SELECTOR = 0x00000c00,
    CS_SELECTOR = 0x00000c02,
    SS_SELECTOR = 0x00000c04,
    DS_SELECTOR = 0x00000c06,
    FS_SELECTOR = 0x00000c08,
    GS_SELECTOR = 0x00000c0a,
    TR_SELECTOR = 0x00000c0c,
}

#[vmcs_access(32, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField32Control {
    PIN_BASED_VM_EXEC_CONTROL           = 0x00004000,
    PROC_BASED_VM_EXEC_CONTROL          = 0x00004002,
    EXCEPTION_BITMAP                    = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK          = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH         = 0x00004008,
    CR3_TARGET_COUNT                    = 0x0000400a,
    VM_EXIT_CONTROLS                    = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT             = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT              = 0x00004010,
    VM_ENTRY_CONTROLS                   = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT             = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD            = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE       = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN            = 0x0000401a,
    TPR_THRESHOLD                       = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL           = 0x0000401e,
    PLE_GAP                             = 0x00004020,
    PLE_WINDOW                          = 0x00004022,
}

#[vmcs_access(32, "R")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField32ReadOnly {
    VM_INSTRUCTION_ERROR        = 0x00004400,
    VM_EXIT_REASON              = 0x00004402,
    VM_EXIT_INTR_INFO           = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE     = 0x00004406,
    IDT_VECTORING_INFO_FIELD    = 0x00004408,
    IDT_VECTORING_ERROR_CODE    = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN     = 0x0000440c,
    VMX_INSTRUCTION_INFO        = 0x0000440e,
}

#[vmcs_access(32, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField32Guest {
    ES_LIMIT                    = 0x00004800,
    CS_LIMIT                    = 0x00004802,
    SS_LIMIT                    = 0x00004804,
    DS_LIMIT                    = 0x00004806,
    FS_LIMIT                    = 0x00004808,
    GS_LIMIT                    = 0x0000480a,
    LDTR_LIMIT                  = 0x0000480c,
    TR_LIMIT                    = 0x0000480e,
    GDTR_LIMIT                  = 0x00004810,
    IDTR_LIMIT                  = 0x00004812,
    ES_AR_BYTES                 = 0x00004814,
    CS_AR_BYTES                 = 0x00004816,
    SS_AR_BYTES                 = 0x00004818,
    DS_AR_BYTES                 = 0x0000481a,
    FS_AR_BYTES                 = 0x0000481c,
    GS_AR_BYTES                 = 0x0000481e,
    LDTR_AR_BYTES               = 0x00004820,
    TR_AR_BYTES                 = 0x00004822,
    INTERRUPTIBILITY_INFO       = 0x00004824,
    ACTIVITY_STATE              = 0x00004826,
    SYSENTER_CS                 = 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE  = 0x0000482E,
}


#[vmcs_access(32, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField32Host {
    IA32_SYSENTER_CS = 0x00004c00,
}

#[vmcs_access(64, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField64Control {
    IO_BITMAP_A             = 0x00002000,
    IO_BITMAP_B             = 0x00002002,
    MSR_BITMAP              = 0x00002004,
    VM_EXIT_MSR_STORE_ADDR  = 0x00002006,
    VM_EXIT_MSR_LOAD_ADDR   = 0x00002008,
    VM_ENTRY_MSR_LOAD_ADDR  = 0x0000200a,
    PML_ADDRESS             = 0x0000200e,
    TSC_OFFSET              = 0x00002010,
    VIRTUAL_APIC_PAGE_ADDR  = 0x00002012,
    APIC_ACCESS_ADDR        = 0x00002014,
    POSTED_INTR_DESC_ADDR   = 0x00002016,
    VM_FUNCTION_CONTROL     = 0x00002018,
    EPT_POINTER             = 0x0000201a,
    EOI_EXIT_BITMAP0        = 0x0000201c,
    EOI_EXIT_BITMAP1        = 0x0000201e,
    EOI_EXIT_BITMAP2        = 0x00002020,
    EOI_EXIT_BITMAP3        = 0x00002022,
    EPTP_LIST_ADDRESS       = 0x00002024,
    VMREAD_BITMAP           = 0x00002026,
    VMWRITE_BITMAP          = 0x00002028,
    XSS_EXIT_BITMAP         = 0x0000202c,
    ENCLS_EXITING_BITMAP    = 0x0000202e,
    TSC_MULTIPLIER          = 0x00002032,

    /* Natural Width */
    CR0_GUEST_HOST_MASK     = 0x00006000,
    CR4_GUEST_HOST_MASK     = 0x00006002,
    CR0_READ_SHADOW         = 0x00006004,
    CR4_READ_SHADOW         = 0x00006006,
    CR3_TARGET_VALUE0       = 0x00006008,
    CR3_TARGET_VALUE1       = 0x0000600a,
    CR3_TARGET_VALUE2       = 0x0000600c,
    CR3_TARGET_VALUE3       = 0x0000600e,
}

#[vmcs_access(64, "R")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField64ReadOnly {
    GUEST_PHYSICAL_ADDRESS      = 0x00002400,

    /* Natural Width */
    EXIT_QUALIFICATION          = 0x00006400,
    IO_RCX                      = 0x00006402,
    IO_RSI                      = 0x00006404,
    IO_RDI                      = 0x00006406,
    IO_RIP                      = 0x00006408,
    GUEST_LINEAR_ADDRESS        = 0x0000640a,
}

#[vmcs_access(64, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField64Guest {
    VMCS_LINK_POINTER               = 0x00002800,
    IA32_DEBUGCTL                   = 0x00002802,
    IA32_PAT                        = 0x00002804,
    IA32_EFER                       = 0x00002806,
    IA32_PERF_GLOBAL_CTRL           = 0x00002808,
    PDPTR0                          = 0x0000280a,
    PDPTR1                          = 0x0000280c,
    PDPTR2                          = 0x0000280e,
    PDPTR3                          = 0x00002810,
    BNDCFGS                         = 0x00002812,

    /* Natural Width */
    CR0                             = 0x00006800,
    CR3                             = 0x00006802,
    CR4                             = 0x00006804,
    ES_BASE                         = 0x00006806,
    CS_BASE                         = 0x00006808,
    SS_BASE                         = 0x0000680a,
    DS_BASE                         = 0x0000680c,
    FS_BASE                         = 0x0000680e,
    GS_BASE                         = 0x00006810,
    LDTR_BASE                       = 0x00006812,
    TR_BASE                         = 0x00006814,
    GDTR_BASE                       = 0x00006816,
    IDTR_BASE                       = 0x00006818,
    DR7                             = 0x0000681a,
    RSP                             = 0x0000681c,
    RIP                             = 0x0000681e,
    RFLAGS                          = 0x00006820,
    PENDING_DBG_EXCEPTIONS          = 0x00006822,
    SYSENTER_ESP                    = 0x00006824,
    SYSENTER_EIP                    = 0x00006826,
}

#[vmcs_access(64, "RW")]
#[derive(Debug, Copy, Clone)]
pub enum VMCSField64Host {
    IA32_PAT                    = 0x00002c00,
    IA32_EFER                   = 0x00002c02,
    IA32_PERF_GLOBAL_CTRL       = 0x00002c04,

    /* Natural Width */
    CR0                         = 0x00006c00,
    CR3                         = 0x00006c02,
    CR4                         = 0x00006c04,
    FS_BASE                     = 0x00006c06,
    GS_BASE                     = 0x00006c08,
    TR_BASE                     = 0x00006c0a,
    GDTR_BASE                   = 0x00006c0c,
    IDTR_BASE                   = 0x00006c0e,
    IA32_SYSENTER_ESP           = 0x00006c10,
    IA32_SYSENTER_EIP           = 0x00006c12,
    RSP                         = 0x00006c14,
    RIP                         = 0x00006c16,
}

pub struct VMCS {
    launched: bool,
    address: u64,
}

#[derive(Debug)]
pub enum VMCSValidationFailure {
    PinBasedVmExecContrlFail,
    PrimaryProcBasedVmExecControlFail,
    SecondaryProcBasedVmExecContorlFail,
    VmExitControlFail,
    VmEntryControlFail,
    Cr3TargetCountFail,
    IoBitmapAAligned,
    IoBitmapBAligned,
    MsrBitmapAligned,
    VirtualApicPageAligned,
    TprThresholdA,
    TprThresholdB,
    Nmi1,
    Nmi2,
    TprShadowNotSet,
    X2Apic,
    VirtualInterruptDelivery1,
    PostedInterrupt1,
    PostedInterrupt2,
    PostedInterrupt3,
    PostedInterrupt4,
    PostedInterrupt5,
    VPID,
}

pub enum VMCSControl {
    PinBasedVmExecControl,
    PrimaryProcBasedVmExecControl,
    SecondaryProcBasedVmExecControl,
    VmExitControl,
    VmEntryControl,
}

/// todo@
fn max_address() -> u64 {
    return 0;
}

impl VMCS {
    pub unsafe fn get() -> u64 {
        /* @todo seems to cause a compiler crash! */
        //let mut value: u64 = 0;
        //asm!("vmptrst $0": "=m" (value));
        //value
        0
    }

    pub fn new(address: u64) -> Option<Self> {
        if !address.aligned(SHIFT_4K) {
            return None;
        }

        Some(VMCS {
            launched: false,
            address: address,
        })
    }

    pub unsafe fn run(&mut self, regs: &mut VcpuGuestRegs) -> bool {
        if self.launched {
            vmx_vmresume(regs)
        } else {
            self.launched = vmx_vmlaunch(regs);
            self.launched
        }
    }

    pub unsafe fn load(&mut self) -> bool {
        let error: bool;
        /* @todo seems to cause a compiler crash */
        //asm!("vmptrld $1; setna $0": "=qm" (error) : "m" (self.address));
        asm!("vmptrld $0":: "m" (self.address));

        VMCSField64Host::RIP.write(vmx_return as u64);
        true
    }

    pub unsafe fn clear(&mut self) -> bool {
        asm!("vmclear $0":: "m" (self.address));
        self.launched = false;
        true
    }

    pub unsafe fn skip_instruction() -> u32 {
        unsafe {
            let len = VMCSField32ReadOnly::VM_EXIT_INSTRUCTION_LEN.read();
            let ip = VMCSField64Guest::RIP.read();

            VMCSField64Guest::RIP.write(ip + len as u64);

            len
        }
    }

    // A.3, A.4, and A.5
    fn adjust_controls(vmx_basic: u64, control: VMCSControl, value: u32) -> u32 {
        let mut result = value;
        let mut msr =
            if (vmx_basic & (1 << 55)) != 0 {
                match control {
                    VMCSControl::PinBasedVmExecControl => MSR::IA32_VMX_TRUE_PINBASED_CTLS,
                    VMCSControl::PrimaryProcBasedVmExecControl => MSR::IA32_VMX_TRUE_PROCBASED_CTLS,
                    VMCSControl::SecondaryProcBasedVmExecControl => MSR::IA32_VMX_PROCBASED_CTLS2,
                    VMCSControl::VmEntryControl => MSR::IA32_VMX_TRUE_EXIT_CTLS,
                    VMCSControl::VmExitControl => MSR::IA32_VMX_TRUE_ENTRY_CTLS,
                }
            } else {
                match control {
                    VMCSControl::PinBasedVmExecControl => MSR::IA32_VMX_PINBASED_CTLS,
                    VMCSControl::PrimaryProcBasedVmExecControl => MSR::IA32_VMX_PROCBASED_CTLS,
                    VMCSControl::SecondaryProcBasedVmExecControl => MSR::IA32_VMX_PROCBASED_CTLS2,
                    VMCSControl::VmEntryControl => MSR::IA32_VMX_EXIT_CTLS,
                    VMCSControl::VmExitControl => MSR::IA32_VMX_ENTRY_CTLS,
                }
            };
        let msr_value = unsafe { msr.read() };

        result &= (msr_value >> 32) as u32;
        result |= msr_value as u32;

        result
    }

    // 26.2.1.1
    unsafe fn validate_vmx_exec_control() -> Result<(), VMCSValidationFailure> {
        let vmx_basic = MSR::IA32_VMX_BASIC.read();
        let pin_based_vm_exec = VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.read();
        let proc_based_vm_exec = VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.read();
        let secondary_proc_based_vm_exec = VMCSField32Control::SECONDARY_VM_EXEC_CONTROL.read();
        let vmexit_controls = VMCSField32Control::VM_EXIT_CONTROLS.read();

        if pin_based_vm_exec !=
            Self::adjust_controls(vmx_basic,
                                  VMCSControl::PinBasedVmExecControl,
                                  pin_based_vm_exec) {
            return Err(VMCSValidationFailure::PinBasedVmExecContrlFail);
        }

        if proc_based_vm_exec !=
            Self::adjust_controls(vmx_basic,
                                  VMCSControl::PrimaryProcBasedVmExecControl,
                                  proc_based_vm_exec) {
            return Err(VMCSValidationFailure::PrimaryProcBasedVmExecControlFail);
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::SECONDARY_CONTROLS.bits()) != 0 {
            if secondary_proc_based_vm_exec !=
                Self::adjust_controls(vmx_basic,
                                      VMCSControl::SecondaryProcBasedVmExecControl,
                                      secondary_proc_based_vm_exec) {
                return Err(VMCSValidationFailure::SecondaryProcBasedVmExecContorlFail);
            }
        }

        let cr3_target_count = ((vmx_basic >> 16) & 0x1ff) as u32;
        if VMCSField32Control::CR3_TARGET_COUNT.read() > cr3_target_count {
            return Err(VMCSValidationFailure::Cr3TargetCountFail);
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::USE_IO_BITMAPS.bits()) != 0 {
            if !VMCSField64Control::IO_BITMAP_A.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::IoBitmapAAligned)
            }

            if !VMCSField64Control::IO_BITMAP_A.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::IoBitmapBAligned)
            }
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::USE_MSR_BITMAP.bits()) != 0 {
            if !VMCSField64Control::MSR_BITMAP.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::MsrBitmapAligned)
            }
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::USE_TPR_SHADOW.bits()) != 0 {
            let apic_addr = VMCSField64Control::VIRTUAL_APIC_PAGE_ADDR.read();
            if !apic_addr.aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::VirtualApicPageAligned);
            }
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::USE_TPR_SHADOW.bits()) != 0 &&
            (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY.bits()) == 0 {
            let tpr_threshold = VMCSField32Control::TPR_THRESHOLD.read();

            if tpr_threshold & 0xffff_fff0 != 0 {
                return Err(VMCSValidationFailure::TprThresholdA);
            }

            /* @todo
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUALIZE_APIC_ACCESSES.bits()) == 0 {
                if tpr_threshold > vtpr {
                    return Err(VMCSValidationFailure::TprThresholdB);
                }
            }
            */
        }

        if (pin_based_vm_exec & PinVMExecControl::NMI_EXITING.bits()) == 0 &&
            (pin_based_vm_exec & PinVMExecControl::VIRTUAL_NMIS.bits()) != 0 {
            return Err(VMCSValidationFailure::Nmi1);
        }

        if (pin_based_vm_exec & PinVMExecControl::NMI_EXITING.bits()) == 0 &&
            (proc_based_vm_exec & PrimaryVMExecControl::NMI_WINDOW_EXITING.bits()) != 0 {
            return Err(VMCSValidationFailure::Nmi2);
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::USE_TPR_SHADOW.bits()) == 0 {
            if (secondary_proc_based_vm_exec &
                (SecondaryVMExecControl::VIRTUALIZE_X2APIC_MODE |
                    SecondaryVMExecControl::APIC_REGISTER_VIRTUALIZATION |
                    SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY).bits()) != 0 {
                return Err(VMCSValidationFailure::TprShadowNotSet)
            }
        }

        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUALIZE_X2APIC_MODE.bits()) != 0 {
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUALIZE_APIC_ACCESSES.bits()) != 0 {
                return Err(VMCSValidationFailure::X2Apic);
            }
        }

        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY.bits()) != 0 {
            if (pin_based_vm_exec & PinVMExecControl::EXTERNAL_INTERRUPT_EXIT.bits()) == 0 {
                return Err(VMCSValidationFailure::VirtualInterruptDelivery1);
            }
        }

        if (pin_based_vm_exec & PinVMExecControl::POSTED_INTERRUPTS.bits()) != 0 {
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY.bits()) == 0 {
                return Err(VMCSValidationFailure::PostedInterrupt1);
            }

            if (vmexit_controls & VMExitControls::ACK_INTERRUPT_ON_EXIT.bits()) != 0 {
                return Err(VMCSValidationFailure::PostedInterrupt2);
            }

            let posted_interrupt_vector = VMCSField16Control::POSTED_INTR_NV.read();

            if (posted_interrupt_vector & 0xff_00) != 0 {
                return Err(VMCSValidationFailure::PostedInterrupt3);
            }

            if (posted_interrupt_vector & 0x1f) != 0 {
                return Err(VMCSValidationFailure::PostedInterrupt4);
            }

            let posted_interrupt_desc = VMCSField64Control::POSTED_INTR_DESC_ADDR.read();

            if posted_interrupt_desc > max_address() {
                return Err(VMCSValidationFailure::PostedInterrupt5);
            }
        }

        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VPID.bits()) != 0 {
            if VMCSField16Control::VIRTUAL_PROCESSOR_ID.read() == 0 {
                return Err(VMCSValidationFailure::VPID);
            }
        }

        return Ok(());

    }

    /* 26.2.1.2 */
    unsafe fn validate_vmx_exit_control() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    /* 26.2.1.3 */
    unsafe fn validate_vmx_entry_control() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    /* 26.2.1 */
    unsafe fn validate_vmx_controls() -> Result<(), VMCSValidationFailure> {
        Self::validate_vmx_exec_control()?;
        Self::validate_vmx_exit_control()?;
        Self::validate_vmx_entry_control()?;
        Ok(())
    }

    unsafe fn validate_host_state() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    unsafe fn validate_guest_state() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    pub unsafe fn validate() -> Result<(), VMCSValidationFailure> {
        Self::validate_vmx_controls()?;
        Self::validate_host_state()?;
        Self::validate_guest_state()?;
        Ok(())
    }
}
