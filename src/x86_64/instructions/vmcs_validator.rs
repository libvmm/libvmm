use crate::{AlignedAddress, SHIFT_4K};
use crate::x86_64::instructions::vmcs::*;
use crate::x86_64::instructions::msr::*;

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

/// todo@
fn max_address() -> u64 {
    return 0;
}

impl VMCS {
    // 26.2.1.1
    unsafe fn validate_vmx_exec_control() -> Result<(), VMCSValidationFailure> {
        let vmx_basic = MSR::IA32_VMX_BASIC.read();
        let pin_based_vm_exec = VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.read();
        let proc_based_vm_exec = VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.read();
        let secondary_proc_based_vm_exec = VMCSField32Control::SECONDARY_VM_EXEC_CONTROL.read();
        let vmexit_controls = VMCSField32Control::VM_EXIT_CONTROLS.read();

        if pin_based_vm_exec !=
            Self::adjust_controls(vmx_basic,
                                  VMCSControl::PinBasedVmExec,
                                  pin_based_vm_exec) {
            return Err(VMCSValidationFailure::PinBasedVmExecContrlFail);
        }

        if proc_based_vm_exec !=
            Self::adjust_controls(vmx_basic,
                                  VMCSControl::PrimaryProcBasedVmExec,
                                  proc_based_vm_exec) {
            return Err(VMCSValidationFailure::PrimaryProcBasedVmExecControlFail);
        }

        if (proc_based_vm_exec & PrimaryVMExecControl::SECONDARY_CONTROLS.bits()) != 0 {
            if secondary_proc_based_vm_exec !=
                Self::adjust_controls(vmx_basic,
                                      VMCSControl::SecondaryProcBasedVmExec,
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