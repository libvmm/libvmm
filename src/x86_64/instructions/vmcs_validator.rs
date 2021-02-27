use crate::x86_64::instructions::msr::*;
use crate::x86_64::instructions::vmcs::*;
use crate::{AlignedAddress, SHIFT_4K};

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
    EptMemTypeUC,
    EptMemTypeWB,
    EptIncorrectPageWalkLength,
    EptAccessedDirty,
    EptReservedBitsLow,
    PmlWithNoEpt,
    PmlAddressAligned,
    UnrestrictedGuestWithNoEpt,
    SubPageWritePermWithNoEpt,
    SPPTPointerAligned,
    VmReadBitmapAligned,
    VmWriteBitmapAligned,
    VirtualizationExceptionInfromationAddressAligned,
    PtUseGpa,
    TscMultiplier,
}

/// todo@
fn max_address() -> u64 {
    return 0;
}

impl VMCS {
    // 26.2.1.1
    fn validate_vmx_exec_control() -> Result<(), VMCSValidationFailure> {
        let pin_based_vm_exec = VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.read();
        let vmx_basic = unsafe { MSR::IA32_VMX_BASIC.read() };
        let vmx_misc = unsafe { MSR::IA32_VMX_MISC_MSR.read() };
        let primary_proc_based_vm_exec =
            VMCSField32Control::PRIMARY_PROC_BASED_VM_EXEC_CONTROL.read();
        let secondary_proc_based_vm_exec = VMCSField32Control::SECONDARY_VM_EXEC_CONTROL.read();
        let vmentry_controls = VMCSField32Control::VM_ENTRY_CONTROLS.read();
        let vmexit_controls = VMCSField32Control::VM_EXIT_CONTROLS.read();

        /*
         * Reserved bits in the pin-based VM-execution controls must be set properly.
         * Software may consult the VMX capability MSRs to determine the proper
         * settings (see Appendix A.3.1).
         */
        if pin_based_vm_exec
            != Self::adjust_controls(vmx_basic, VMCSControl::PinBasedVmExec, pin_based_vm_exec)
        {
            return Err(VMCSValidationFailure::PinBasedVmExecContrlFail);
        }

        /*
         * Reserved bits in the primary processor-based VM-execution controls
         * must be set properly. Software may consult the VMX capability MSRs
         * to determine the proper settings (see Appendix A.3.2).
         */
        if primary_proc_based_vm_exec
            != Self::adjust_controls(
                vmx_basic,
                VMCSControl::PrimaryProcBasedVmExec,
                primary_proc_based_vm_exec,
            )
        {
            return Err(VMCSValidationFailure::PrimaryProcBasedVmExecControlFail);
        }

        /*
         * If the “activate secondary controls” primary processor-based
         * VM-execution control is 1, reserved bits in the secondary
         * processor-based VM-execution controls must be cleared. Software
         * may consult the VMX capability MSRs to determine which bits are
         * reserved (see Appendix A.3.3)
         */
        if (primary_proc_based_vm_exec & PrimaryVMExecControl::SECONDARY_CONTROLS.bits()) != 0 {
            if secondary_proc_based_vm_exec
                != Self::adjust_controls(
                    vmx_basic,
                    VMCSControl::SecondaryProcBasedVmExec,
                    secondary_proc_based_vm_exec,
                )
            {
                return Err(VMCSValidationFailure::SecondaryProcBasedVmExecContorlFail);
            }
        }

        /*
         * The CR3-target count must not be greater than 4. Future
         * processors may support a different number of CR3-target values.
         * Software should read the VMX capability MSR IA32_VMX_MISC to
         * determine the number of values supported.
         */
        let cr3_target_count = ((vmx_misc >> 16) & 0x1ff) as u32;
        if VMCSField32Control::CR3_TARGET_COUNT.read() > cr3_target_count {
            return Err(VMCSValidationFailure::Cr3TargetCountFail);
        }

        /*
         * If the “use I/O bitmaps” VM-execution control is 1, bits 11:0
         * of each I/O-bitmap address must be 0. Neither address should
         * set any bits beyond the processor’s physical-address width. (MISSING)
         */
        if (primary_proc_based_vm_exec & PrimaryVMExecControl::USE_IO_BITMAPS.bits()) != 0 {
            if !VMCSField64Control::IO_BITMAP_A.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::IoBitmapAAligned);
            }

            if !VMCSField64Control::IO_BITMAP_B.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::IoBitmapBAligned);
            }
        }

        /*
         * If the “use MSR bitmaps” VM-execution control is 1, bits 11:0
         * of the MSR-bitmap address must be 0. The address should not
         * set any bits beyond the processor’s physical-address width. (MISSING)
         */
        if (primary_proc_based_vm_exec & PrimaryVMExecControl::USE_MSR_BITMAP.bits()) != 0 {
            if !VMCSField64Control::MSR_BITMAP.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::MsrBitmapAligned);
            }
        }

        /*
         * If the “use TPR shadow” VM-execution control is 1, the
         * virtual-APIC address must satisfy the following checks:
         *    — Bits 11:0 of the address must be 0.
         *    — The address should not set any bits beyond the processor’s
         *      physical-address width. (MISSING)
         */
        if (primary_proc_based_vm_exec & PrimaryVMExecControl::USE_TPR_SHADOW.bits()) != 0 {
            let apic_addr = VMCSField64Control::VIRTUAL_APIC_PAGE_ADDR.read();
            if !apic_addr.aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::VirtualApicPageAligned);
            }
        }

        /*
         * If the “use TPR shadow” VM-execution control is 1 and the
         * “virtual-interrupt delivery” VM-execution control is 0, bits
         * 31:4 of the TPR threshold VM-execution control field must be 0.
         */
        if (primary_proc_based_vm_exec & PrimaryVMExecControl::USE_TPR_SHADOW.bits()) != 0
            && (secondary_proc_based_vm_exec
                & SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY.bits())
                == 0
        {
            let tpr_threshold = VMCSField32Control::TPR_THRESHOLD.read();

            if tpr_threshold & 0xffff_fff0 != 0 {
                return Err(VMCSValidationFailure::TprThresholdA);
            }

            /*
             * The following check is performed if the “use TPR shadow” VM-execution
             * control is 1 and the “virtualize APIC acesses” and
             * “virtual-interrupt delivery” VM-execution controls are both 0: the
             * value of bits 3:0 of the TPR threshold VM-execution control field
             * should not be greater than the value of bits 7:4 of VTPR
             */

            /* @todo
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUALIZE_APIC_ACCESSES.bits()) == 0 {
                if tpr_threshold > vtpr {
                    return Err(VMCSValidationFailure::TprThresholdB);
                }
            }
            */
        }

        /*
         * If the “NMI exiting” VM-execution control is 0, the “virtual NMIs” VM-execution control
         * must be 0.
         */
        if (pin_based_vm_exec & PinVMExecControl::NMI_EXITING.bits()) == 0
            && (pin_based_vm_exec & PinVMExecControl::VIRTUAL_NMIS.bits()) != 0
        {
            return Err(VMCSValidationFailure::Nmi1);
        }

        /*
         * If the “virtual NMIs” VM-execution control is 0, the “NMI-window exiting” VM-execution
         * control must be 0.
         */
        if (pin_based_vm_exec & PinVMExecControl::VIRTUAL_NMIS.bits()) == 0
            && (primary_proc_based_vm_exec & PrimaryVMExecControl::NMI_WINDOW_EXITING.bits()) != 0
        {
            return Err(VMCSValidationFailure::Nmi2);
        }

        /*
         * If the “virtualize APIC-accesses” VM-execution control is 1, the APIC-access address
         * must satisfy the following checks:
         *   — Bits 11:0 of the address must be 0.
         *   — The address should not set any bits beyond the processor’s physical-address
         *     width.
         *
         * TODO: Validation of this condition is missing.
         */

        /*
         * If the “use TPR shadow” VM-execution control is 0, the following VM-execution controls
         * must also be 0: “virtualize x2APIC mode”, “APIC-register virtualization”, and
         * “virtual-interrupt delivery”.
         */
        if (primary_proc_based_vm_exec & PrimaryVMExecControl::USE_TPR_SHADOW.bits()) == 0 {
            if (secondary_proc_based_vm_exec
                & (SecondaryVMExecControl::VIRTUALIZE_X2APIC_MODE
                    | SecondaryVMExecControl::APIC_REGISTER_VIRTUALIZATION
                    | SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY)
                    .bits())
                != 0
            {
                return Err(VMCSValidationFailure::TprShadowNotSet);
            }
        }

        /*
         * If the “virtualize x2APIC mode” VM-execution control is 1, the “virtualize APIC accesses”
         * VM-execution control must be 0.
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VIRTUALIZE_X2APIC_MODE.bits())
            != 0
        {
            if (secondary_proc_based_vm_exec
                & SecondaryVMExecControl::VIRTUALIZE_APIC_ACCESSES.bits())
                != 0
            {
                return Err(VMCSValidationFailure::X2Apic);
            }
        }

        /*
         * If the “virtual-interrupt delivery” VM-execution control is 1, the “external-interrupt
         * exiting” VM-execution control must be 1.
         */
        if (secondary_proc_based_vm_exec
            & SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY.bits())
            != 0
        {
            if (pin_based_vm_exec & PinVMExecControl::EXTERNAL_INTERRUPT_EXIT.bits()) == 0 {
                return Err(VMCSValidationFailure::VirtualInterruptDelivery1);
            }
        }

        /*
         * If the “process posted interrupts” VM-execution control is 1, the following must be true:
         */
        if (pin_based_vm_exec & PinVMExecControl::POSTED_INTERRUPTS.bits()) != 0 {
            /*
             * The “virtual-interrupt delivery” VM-execution control is 1.
             */
            if (secondary_proc_based_vm_exec
                & SecondaryVMExecControl::VIRTUAL_INTERRUPT_DELIVERY.bits())
                == 0
            {
                return Err(VMCSValidationFailure::PostedInterrupt1);
            }

            /*
             * The “acknowledge interrupt on exit” VM-exit control is 1.
             */
            if (vmexit_controls & VMExitControls::ACK_INTERRUPT_ON_EXIT.bits()) != 0 {
                return Err(VMCSValidationFailure::PostedInterrupt2);
            }

            /*
             * The posted-interrupt notification vector has a value in the range 0–255
             * (bits 15:8 are all 0).
             */
            let posted_interrupt_vector = VMCSField16Control::POSTED_INTR_NV.read();
            if (posted_interrupt_vector & 0xff_00) != 0 {
                return Err(VMCSValidationFailure::PostedInterrupt3);
            }

            /*
             * Bits 5:0 of the posted-interrupt descriptor address are all 0.
             */
            if (posted_interrupt_vector & 0x1f) != 0 {
                return Err(VMCSValidationFailure::PostedInterrupt4);
            }

            /*
             * The posted-interrupt descriptor address does not set any bits beyond the processor's
             * physical-address width.
             */
            let posted_interrupt_desc = VMCSField64Control::POSTED_INTR_DESC_ADDR.read();
            if posted_interrupt_desc > max_address() {
                return Err(VMCSValidationFailure::PostedInterrupt5);
            }
        }

        /*
         * If the “enable VPID” VM-execution control is 1, the value of the VPID VM-execution
         * control field must not be 0000H.
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VPID.bits()) != 0 {
            if VMCSField16Control::VIRTUAL_PROCESSOR_ID.read() == 0 {
                return Err(VMCSValidationFailure::VPID);
            }
        }

        /*
         * If the “enable EPT” VM-execution control is 1, the EPTP VM-execution control field
         * (see Table 24-8 in Section 24.6.11) must satisfy the following checks: 4
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::EPT.bits()) != 0 {
            let ept_pointer = VMCSField64Control::EPT_POINTER.read();
            let vmx_ept_vpid_cap = unsafe { MSR::IA32_VMX_EPT_VPID_CAP.read() };

            /*
             * The EPT memory type (bits 2:0) must be a value supported by the processor as
             * indicated in the IA32_VMX_EPT_VPID_CAP MSR
             */
            let ept_mem_type = ept_pointer & 0x7;
            if (vmx_ept_vpid_cap & EptVpidCap::EPT_MEM_TYPE_UC.bits()) != 0 {
                if ept_mem_type != 0 {
                    return Err(VMCSValidationFailure::EptMemTypeUC);
                }
            }

            if (vmx_ept_vpid_cap & EptVpidCap::EPT_MEM_TYPE_WB.bits()) != 0 {
                if ept_mem_type != 6 {
                    return Err(VMCSValidationFailure::EptMemTypeWB);
                }
            }

            /*
             * Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT
             * page-walk length of 4; see Section 28.2.2.
             */
            let ept_page_walk_length = (ept_pointer >> 3) & 0x7;
            if ept_page_walk_length != 3 {
                return Err(VMCSValidationFailure::EptIncorrectPageWalkLength);
            }

            /*
             * Bit 6 (enable bit for accessed and dirty flags for EPT) must be 0 if bit 21 of the
             * IA32_VMX_EPT_VPID_CAP MSR (see Appendix A.10) is read as 0, indicating that the
             * processor does not support accessed and dirty flags for EPT.
             */
            if (vmx_ept_vpid_cap & EptVpidCap::ACCESSED_DIRTY_FLAG.bits()) == 0 {
                let ept_accessed_dirty = ept_pointer & (1 << 6) as u64;
                if ept_accessed_dirty != 0 {
                    return Err(VMCSValidationFailure::EptAccessedDirty);
                }
            }

            /*
             * Reserved bits 11:7 and TODO: 63:N (where N is the processor’s physical-address width)
             * must all be 0.
             */
            let ept_reserved_bits_low = (ept_pointer >> 7) & ((1 << 5) - 1);
            if ept_reserved_bits_low != 0 {
                return Err(VMCSValidationFailure::EptReservedBitsLow);
            }
        }

        /*
         * If the “enable PML” VM-execution control is 1, the “enable EPT” VM-execution control
         * must also be 1. In addition, the PML address must satisfy the following checks
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::PML.bits()) != 0 {
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::EPT.bits()) == 0 {
                return Err(VMCSValidationFailure::PmlWithNoEpt);
            }

            /* Bits 11:0 of the address must be 0. */
            if !VMCSField64Control::PML_ADDRESS.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::PmlAddressAligned);
            }

            /* TODO: The address should not set any bits beyond the processor’s physical-address
             * width. */
        }

        /*
         * If either the “unrestricted guest” VM-execution control or the “mode-based execute
         * control for EPT” VM-execution control is 1, the “enable EPT” VM-execution control must
         * also be 1.
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::UNRESTRICTED_GUEST.bits()) != 0
            || (secondary_proc_based_vm_exec & SecondaryVMExecControl::EXECUTE_CONTROL_EPT.bits())
                != 0
        {
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::EPT.bits()) == 0 {
                return Err(VMCSValidationFailure::UnrestrictedGuestWithNoEpt);
            }
        }

        /*
         * If the “sub-page write permissions for EPT” VM-execution control is 1, the “enable EPT”
         * VM-execution control must also be 1. In addition, the SPPTP VM-execution control field
         * (see Table 24-10 in Section 24.6.21) must satisfy the following checks:
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::SUB_PAGE_WRITE_PERM_EPT.bits())
            != 0
        {
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::EPT.bits()) == 0 {
                return Err(VMCSValidationFailure::SubPageWritePermWithNoEpt);
            }

            /* Bits 11:0 of the address must be 0. */
            if !VMCSField64Control::SPPT_POINTER.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::SPPTPointerAligned);
            }

            /* TODO: The address should not set any bits beyond the processor’s physical-address
             * width. */
        }

        /*
         * If the “VMCS shadowing” VM-execution control is 1, the VMREAD-bitmap and VMWRITE-bitmap
         * addresses must each satisfy the following checks:
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::VMCS_SHADOWING.bits()) != 0 {
            /*
             * Bits 11:0 of the address must be 0.
             */
            if !VMCSField64Control::VMREAD_BITMAP.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::VmReadBitmapAligned);
            }

            if !VMCSField64Control::VMWRITE_BITMAP.read().aligned(SHIFT_4K) {
                return Err(VMCSValidationFailure::VmWriteBitmapAligned);
            }

            /*
             * TODO: The address must not set any bits beyond the processor’s physical-address
             * width.
             */
        }

        /*
         * If the “EPT-violation #VE” VM-execution control is 1, the virtualization-exception
         * information address must satisfy the following checks:
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::EPT_VIOLATION_VE.bits()) != 0 {
            /*
             * Bits 11:0 of the address must be 0.
             */
            if !VMCSField64Control::VIRTUALIZATION_EXCEPTION_INFROMATION_ADDRESS
                .read()
                .aligned(SHIFT_4K)
            {
                return Err(
                    VMCSValidationFailure::VirtualizationExceptionInfromationAddressAligned,
                );
            }

            /*
             * TODO: The address must not set any bits beyond the processor’s physical-address
             * width.
             */
        }

        /*
         * If the “Intel PT uses guest physical addresses” VM-execution control is 1, the following
         * controls must also be 1:
         *   - the “enable EPT” VM-execution control;
         *   - the “load IA32_RTIT_CTL” VM-entry control; and
         *   - the “clear IA32_RTIT_CTL” VM-exit control
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::PT_USE_GPA.bits()) != 0 {
            if (secondary_proc_based_vm_exec & SecondaryVMExecControl::EPT.bits()) == 0
                || (vmentry_controls & VMEntryControls::LOAD_IA32_RTIT_CTL.bits()) == 0
                || (vmexit_controls & VMExitControls::CLEAR_IA32_RTIT_CTL.bits()) == 0
            {
                return Err(VMCSValidationFailure::PtUseGpa);
            }
        }

        /*
         * If the “use TSC scaling” VM-execution control is 1, the TSC-multiplier must not be zero.
         */
        if (secondary_proc_based_vm_exec & SecondaryVMExecControl::TSC_SCALING.bits()) != 0 {
            let tsc_multiplier = VMCSField64Control::TSC_MULTIPLIER.read();
            if tsc_multiplier == 0 {
                return Err(VMCSValidationFailure::TscMultiplier);
            }
        }

        return Ok(());
    }

    /* 26.2.1.2 */
    fn validate_vmx_exit_control() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    /* 26.2.1.3 */
    fn validate_vmx_entry_control() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    /* 26.2.1 */
    fn validate_vmx_controls() -> Result<(), VMCSValidationFailure> {
        Self::validate_vmx_exec_control()?;
        Self::validate_vmx_exit_control()?;
        Self::validate_vmx_entry_control()?;
        Ok(())
    }

    fn validate_host_state() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    fn validate_guest_state() -> Result<(), VMCSValidationFailure> {
        Ok(())
    }

    pub fn validate() -> Result<(), VMCSValidationFailure> {
        Self::validate_vmx_controls()?;
        Self::validate_host_state()?;
        Self::validate_guest_state()?;
        Ok(())
    }
}
