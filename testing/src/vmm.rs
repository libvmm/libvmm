use crate::emulator::*;
use libos::page_alloc::page_alloc;
use libos::println;
use libos::vm::VM;
use libos::pic::PIC;
use libos::interrupt_controller::InterruptController;
use libvmm::x86_64::interrupts::injection::*;
use libvmm::x86_64::instructions::exits::*;
use libvmm::x86_64::instructions::msr::*;
use libvmm::x86_64::instructions::vmcs::*;
use libvmm::x86_64::instructions::vmcs_validator::*;
use libvmm::x86_64::instructions::VMX;
use libvmm::x86_64::structures::ept::*;
use libvmm::x86_64::structures::guest::VcpuGuestRegs;
use libvmm::x86_64::structures::io::IOBitmap;
use libvmm::PAGE_4K;
use x86_64::registers::control::*;
use x86_64::registers::model_specific::Efer;
use x86_64::registers::rflags;
use x86_64::structures::paging::{FrameAllocator, PhysFrame};
use x86_64::structures::DescriptorTablePointer;

fn get_gdt() -> DescriptorTablePointer {
    let gdt = DescriptorTablePointer { base: 0, limit: 0 };

    unsafe {
        llvm_asm!("sgdt ($0)":: "r"(&gdt): "memory");
    }

    gdt
}

fn get_idt() -> DescriptorTablePointer {
    let idt = DescriptorTablePointer { base: 0, limit: 0 };

    unsafe {
        llvm_asm!("sidt ($0)":: "r"(&idt): "memory");
    }

    idt
}

fn get_cs() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("mov %cs, $0" : "=r" (segment) ) };
    segment
}

fn get_ds() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("mov %ds, $0" : "=r" (segment) ) };
    segment
}

fn get_es() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("mov %es, $0" : "=r" (segment) ) };
    segment
}

fn get_fs() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("mov %fs, $0" : "=r" (segment) ) };
    segment
}

fn get_ss() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("mov %ss, $0" : "=r" (segment) ) };
    segment
}

fn get_gs() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("mov %gs, $0" : "=r" (segment) ) };
    segment
}

fn get_ldt() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("sldt $0" : "=r" (segment) ) };
    segment
}

fn get_tr() -> u16 {
    let segment: u16;
    unsafe { llvm_asm!("str $0" : "=r" (segment) ) };
    segment
}

fn get_rflags() -> u64 {
    rflags::read_raw()
}

fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        llvm_asm!("mov %cr4, $0" : "=r" (value));
    }
    value
}

fn write_cr4(value: u64) {
    unsafe {
        llvm_asm!("mov $0, %cr4" :: "r" (value));
    }
}

fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        llvm_asm!("mov %cr3, $0" : "=r" (value));
    }
    value
}

fn write_cr3(value: u64) {
    unsafe {
        llvm_asm!("mov $0, %cr3" :: "r" (value));
    }
}

pub struct VMM;

impl VMM {
    pub fn init() -> bool {
        let cpuid = unsafe { core::arch::x86_64::__cpuid(0x1) };
        let vmx = if cpuid.ecx & (1 << 5) == 0 {
            false
        } else {
            true
        };

        if vmx == false {
            return false;
        }

        /* Enable Virt Extensions */
        write_cr4(read_cr4() | (1 << 13));

        let feature_control_value = unsafe { MSR::IA32_FEATURE_CONTROL.read() };

        /*
         * bit[0]: Lock bit.
         * bit[2]: Enable VMXON
         */
        if feature_control_value & 0x0 == 0 {
            if feature_control_value & (1 << 2) == 0 {
                unsafe {
                    MSR::IA32_FEATURE_CONTROL.write(feature_control_value | (1 << 2));
                }
            }
        } else {
            if feature_control_value & (1 << 2) == 0 {
                /* VMX disabled in BIOS */
                return false;
            }
        }

        let vmxon_region = page_alloc().allocate_frame().unwrap();
        let vmxon_vaddr = (VM::phys_to_virt(vmxon_region.start_address().as_u64())) as *mut u32;

        unsafe {
            *vmxon_vaddr = MSR::IA32_VMX_BASIC.read() as u32;
            VMX::vmxon(vmxon_region.start_address().as_u64());
        }

        return true;
    }
}

fn setup_ept() -> EPTPointer {
    let pml4_page = page_alloc().allocate_frame().unwrap();
    let pdp_page = page_alloc().allocate_frame().unwrap();
    let pd_page = page_alloc().allocate_frame().unwrap();
    let pt_page = page_alloc().allocate_frame().unwrap();
    let guest_page = page_alloc().allocate_frame().unwrap();

    let eptp =
        EPTPointer::new(pml4_page.start_address().as_u64(), EPTPFlags::MT_WRITEBACK).unwrap();

    let pml4_table = ept_pml4_table!(VM::phys_to_virt(pml4_page.start_address().as_u64()));
    let pdp_table = ept_pdp_table!(VM::phys_to_virt(pdp_page.start_address().as_u64()));
    let pd_table = ept_pd_table!(VM::phys_to_virt(pd_page.start_address().as_u64()));
    let page_table = ept_page_table!(VM::phys_to_virt(pt_page.start_address().as_u64()));

    let flags = (EPTEntryFlags::READABLE
        | EPTEntryFlags::WRITABLE
        | EPTEntryFlags::SUPERVISOR_EXECUTABLE
        | EPTEntryFlags::USER_EXECUTABLE)
        .bits();

    let pml4_entry = EPTPML4Entry::new(pdp_page.start_address().as_u64(), flags).unwrap();
    let pdp_entry = EPTPDPEntry::new(pd_page.start_address().as_u64(), flags).unwrap();
    let pd_entry = EPTPDEntry::new(pt_page.start_address().as_u64(), flags).unwrap();
    let pt_entry = EPTPTEntry::new(guest_page.start_address().as_u64(), flags).unwrap();

    /* Create a mapping at guest virtual address 0x0000 */
    pml4_table[0x0000] = pml4_entry;
    pdp_table[0x0000] = pdp_entry;
    pd_table[0x0000] = pd_entry;
    page_table[0x0000] = pt_entry;

    let mut address = VM::phys_to_virt(guest_page.start_address().as_u64());

    for byte in include_bytes!("test").iter() {
        unsafe {
            *(address as *mut u8) = *byte;
        }
        address += 1;
    }

    return eptp;
}

fn setup_iobitmap() -> (IOBitmap, PhysFrame, PhysFrame) {
    let bitmap_a_frame = page_alloc().allocate_frame().unwrap();
    let bitmap_a_vaddr = VM::phys_to_virt(bitmap_a_frame.start_address().as_u64());
    let bitmap_b_frame = page_alloc().allocate_frame().unwrap();
    let bitmap_b_vaddr = VM::phys_to_virt(bitmap_b_frame.start_address().as_u64());

    let mut iobitmap = unsafe { IOBitmap::new_raw(bitmap_a_vaddr, bitmap_b_vaddr).unwrap() };

    (iobitmap, bitmap_a_frame, bitmap_b_frame)
}

fn create_vmcs() -> VMCS {
    let vmcs_page = page_alloc().allocate_frame().unwrap();
    let vmcs_vaddr = VM::phys_to_virt(vmcs_page.start_address().as_u64()) as *mut u32;
    let vmcs = VMCS::new(vmcs_page.start_address().as_u64()).unwrap();

    unsafe {
        *vmcs_vaddr = MSR::IA32_VMX_BASIC.read() as u32;
    }

    vmcs
}

fn setup_vmm() -> (IOBitmap, VMCS) {
    VMM::init();

    let eptp: EPTPointer = setup_ept();
    let (iobitmap, bitmap_a_frame, bitmap_b_frame) = setup_iobitmap();
    let mut vmcs = create_vmcs();

    unsafe {
        vmcs.load();

        let secondary_vm_exec_control =
            (SecondaryVMExecControl::UNRESTRICTED_GUEST | SecondaryVMExecControl::EPT).bits();
        let primary_vm_exec_control = (PrimaryVMExecControl::USE_IO_BITMAPS
            | PrimaryVMExecControl::HLT_EXITING
            | PrimaryVMExecControl::SECONDARY_CONTROLS)
            .bits();
        let vmexit_controls = (VMExitControls::IA32E_MODE_GUEST
            | VMExitControls::ACK_INTERRUPT_ON_EXIT
            | VMExitControls::SAVE_PAT
            | VMExitControls::LOAD_PAT
            | VMExitControls::SAVE_EFER
            | VMExitControls::LOAD_EFER)
            .bits();
        let vmentry_controls = (VMEntryControls::LOAD_PAT | VMEntryControls::LOAD_EFER).bits();

        VMCSField16Control::VIRTUAL_PROCESSOR_ID.write(0);
        VMCSField16Control::POSTED_INTR_NV.write(0);
        //VMCSField16Control::EPTP_INDEX.write(0);

        let vmx_basic = MSR::IA32_VMX_BASIC.read();

        VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.write(VMCS::adjust_controls(
            vmx_basic,
            VMCSControl::PinBasedVmExec,
            0,
        ));
        VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.write(VMCS::adjust_controls(
            vmx_basic,
            VMCSControl::PrimaryProcBasedVmExec,
            primary_vm_exec_control,
        ));
        VMCSField32Control::SECONDARY_VM_EXEC_CONTROL.write(VMCS::adjust_controls(
            vmx_basic,
            VMCSControl::SecondaryProcBasedVmExec,
            secondary_vm_exec_control,
        ));
        VMCSField32Control::VM_EXIT_CONTROLS.write(VMCS::adjust_controls(
            vmx_basic,
            VMCSControl::VmExit,
            vmexit_controls,
        ));
        VMCSField32Control::VM_ENTRY_CONTROLS.write(VMCS::adjust_controls(
            vmx_basic,
            VMCSControl::VmEntry,
            vmentry_controls,
        ));

        VMCSField32Control::EXCEPTION_BITMAP.write(0x0);
        VMCSField32Control::PAGE_FAULT_ERROR_CODE_MASK.write(0x0);
        VMCSField32Control::PAGE_FAULT_ERROR_CODE_MATCH.write(0x0);
        VMCSField32Control::CR3_TARGET_COUNT.write(0);
        VMCSField32Control::VM_EXIT_MSR_STORE_COUNT.write(0);
        VMCSField32Control::VM_EXIT_MSR_LOAD_COUNT.write(0);

        VMCSField32Control::VM_ENTRY_MSR_LOAD_COUNT.write(0);
        VMCSField32Control::VM_ENTRY_INTR_INFO_FIELD.write(0);
        VMCSField32Control::VM_ENTRY_EXCEPTION_ERROR_CODE.write(0);
        VMCSField32Control::VM_ENTRY_INSTRUCTION_LEN.write(0);
        VMCSField32Control::TPR_THRESHOLD.write(0);
        //VMCSField32Control::PLE_GAP.write(0);
        //VMCSField32Control::PLE_WINDOW.write(0);

        VMCSField64Control::IO_BITMAP_A.write(bitmap_a_frame.start_address().as_u64());
        VMCSField64Control::IO_BITMAP_B.write(bitmap_b_frame.start_address().as_u64());
        VMCSField64Control::MSR_BITMAP.write(0x0);
        VMCSField64Control::VM_EXIT_MSR_STORE_ADDR.write(0x0);
        VMCSField64Control::VM_EXIT_MSR_LOAD_ADDR.write(0x0);
        VMCSField64Control::VM_ENTRY_MSR_LOAD_ADDR.write(0x0);
        VMCSField64Control::PML_ADDRESS.write(0x0);
        VMCSField64Control::TSC_OFFSET.write(0x0);
        VMCSField64Control::VIRTUAL_APIC_PAGE_ADDR.write(0x0);
        VMCSField64Control::APIC_ACCESS_ADDR.write(0x0);
        VMCSField64Control::POSTED_INTR_DESC_ADDR.write(0x0);
        VMCSField64Control::VM_FUNCTION_CONTROL.write(0x0);
        VMCSField64Control::EPT_POINTER.write(eptp.raw());
        VMCSField64Control::EOI_EXIT_BITMAP0.write(0x0);
        VMCSField64Control::EOI_EXIT_BITMAP1.write(0x0);
        VMCSField64Control::EOI_EXIT_BITMAP2.write(0x0);
        VMCSField64Control::EOI_EXIT_BITMAP3.write(0x0);
        VMCSField64Control::EPTP_LIST_ADDRESS.write(0x0);
        VMCSField64Control::VMREAD_BITMAP.write(0x0);
        VMCSField64Control::VMWRITE_BITMAP.write(0x0);
        VMCSField64Control::XSS_EXIT_BITMAP.write(0x0);
        //VMCSField64Control::ENCLS_EXITING_BITMAP.write(0x0);
        //VMCSField64Control::TSC_MULTIPLIER.write(0x0);
        VMCSField64Control::CR0_GUEST_HOST_MASK.write(0x0);
        VMCSField64Control::CR4_GUEST_HOST_MASK.write(0x0);
        VMCSField64Control::CR0_READ_SHADOW.write(0x0);
        VMCSField64Control::CR4_READ_SHADOW.write(0x0);
        VMCSField64Control::CR3_TARGET_VALUE0.write(0x0);
        VMCSField64Control::CR3_TARGET_VALUE1.write(0x0);
        VMCSField64Control::CR3_TARGET_VALUE2.write(0x0);
        VMCSField64Control::CR3_TARGET_VALUE3.write(0x0);

        /*** Host ***/
        VMCSField64Host::IA32_EFER.write(Efer::read_raw());
        VMCSField64Host::IA32_PAT.write(MSR::IA32_CR_PAT.read());

        VMCSField64Host::CR0.write(Cr0::read_raw());
        VMCSField64Host::CR3.write(read_cr3());
        VMCSField64Host::CR4.write(read_cr4());

        VMCSField64Host::FS_BASE.write(MSR::FS_BASE.read());
        VMCSField64Host::GS_BASE.write(MSR::GS_BASE.read());
        /* todo: fix TR_BASE register */
        VMCSField64Host::TR_BASE.write(0x0);

        VMCSField64Host::GDTR_BASE.write(get_gdt().base);
        VMCSField64Host::IDTR_BASE.write(get_idt().base);

        VMCSField64Host::IA32_SYSENTER_ESP.write(MSR::IA32_SYSENTER_ESP.read());
        VMCSField64Host::IA32_SYSENTER_EIP.write(MSR::IA32_SYSENTER_EIP.read());

        //VMCSField64Host::RIP.write(vmx_return as u64);
        VMCSField32Host::IA32_SYSENTER_CS.write(MSR::IA32_SYSENTER_CS.read() as u32);

        VMCSField16Host::ES_SELECTOR.write(get_es());
        VMCSField16Host::CS_SELECTOR.write(get_cs());
        VMCSField16Host::SS_SELECTOR.write(get_ss());
        VMCSField16Host::DS_SELECTOR.write(get_ds());
        VMCSField16Host::FS_SELECTOR.write(get_fs());
        VMCSField16Host::GS_SELECTOR.write(get_gs());
        VMCSField16Host::TR_SELECTOR.write(get_tr());

        /*** Guest ***/

        VMCSField16Guest::ES_SELECTOR.write(0);
        VMCSField64Guest::ES_BASE.write(0);
        VMCSField32Guest::ES_LIMIT.write(0xffff);
        VMCSField32Guest::ES_AR_BYTES.write(0x93);

        VMCSField16Guest::DS_SELECTOR.write(0);
        VMCSField64Guest::DS_BASE.write(0);
        VMCSField32Guest::DS_LIMIT.write(0xffff);
        VMCSField32Guest::DS_AR_BYTES.write(0x93);

        VMCSField16Guest::SS_SELECTOR.write(0);
        VMCSField64Guest::SS_BASE.write(0x0000);
        VMCSField32Guest::SS_LIMIT.write(0xffff);
        VMCSField32Guest::SS_AR_BYTES.write(0x93);

        VMCSField16Guest::FS_SELECTOR.write(0);
        VMCSField64Guest::FS_BASE.write(0);
        VMCSField32Guest::FS_LIMIT.write(0xffff);
        VMCSField32Guest::FS_AR_BYTES.write(0x93);

        VMCSField16Guest::GS_SELECTOR.write(0);
        VMCSField64Guest::GS_BASE.write(0);
        VMCSField32Guest::GS_LIMIT.write(0xffff);
        VMCSField32Guest::GS_AR_BYTES.write(0x93);

        VMCSField16Guest::CS_SELECTOR.write(0x0000);
        VMCSField64Guest::CS_BASE.write(0x0000);
        VMCSField32Guest::CS_LIMIT.write(0xffff);
        VMCSField32Guest::CS_AR_BYTES.write(0x9b);

        VMCSField16Guest::TR_SELECTOR.write(0);
        VMCSField64Guest::TR_BASE.write(0);
        VMCSField32Guest::TR_LIMIT.write(0xffff);
        VMCSField32Guest::TR_AR_BYTES.write(0x8b);

        VMCSField16Guest::LDTR_SELECTOR.write(0);
        VMCSField64Guest::LDTR_BASE.write(0);
        VMCSField32Guest::LDTR_LIMIT.write(0xffff);
        VMCSField32Guest::LDTR_AR_BYTES.write(0x82);

        VMCSField64Guest::GDTR_BASE.write(0);
        VMCSField32Guest::GDTR_LIMIT.write(0xffff);

        VMCSField64Guest::IDTR_BASE.write(0);
        VMCSField32Guest::IDTR_LIMIT.write(0x3ff);

        //VMCSField16Guest::INTR_STATUS.write(0);
        //VMCSField16Guest::PML_INDEX.write(0);

        VMCSField32Guest::INTERRUPTIBILITY_INFO.write(0x0);
        VMCSField32Guest::ACTIVITY_STATE.write(0x0);
        //VMCSField32Guest::SYSENTER_CS.write(0x0);
        //VMCSField32Guest::VMX_PREEMPTION_TIMER_VALUE.write(0x0);

        VMCSField64Guest::VMCS_LINK_POINTER.write(0xffffffffffffffff);
        //VMCSField64Guest::IA32_DEBUGCTL.write(0x0);
        //VMCSField64Guest::IA32_PAT.write(0);
        VMCSField64Guest::IA32_EFER.write(0);
        VMCSField64Guest::IA32_PERF_GLOBAL_CTRL.write(0);
        VMCSField64Guest::PDPTR0.write(0);
        VMCSField64Guest::PDPTR1.write(0);
        VMCSField64Guest::PDPTR2.write(0);
        VMCSField64Guest::PDPTR3.write(0);
        //VMCSField64Guest::BNDCFGS.write(0);
        VMCSField64Guest::CR0.write((1 << 29) | (1 << 30) | (1 << 5));
        VMCSField64Guest::CR3.write(0);
        VMCSField64Guest::CR4.write(1 << 13);
        VMCSField64Guest::DR7.write(0);
        VMCSField64Guest::RFLAGS.write(0x2);
        //VMCSField64Guest::SYSENTER_EIP.write(0x0);
        //VMCSField64Guest::SYSENTER_ESP.write(0x0);
        VMCSField64Guest::RSP.write(0x1000);
        VMCSField64Guest::RIP.write(0x0800);
        VMCSField64Guest::PENDING_DBG_EXCEPTIONS.write(0x0);
    }

    (iobitmap, vmcs)
}

pub fn run_guest() -> bool {
    let (mut iobitmap, mut vmcs) = setup_vmm();
    let mut regs: VcpuGuestRegs = Default::default();
    let address = page_alloc()
        .allocate_frame()
        .unwrap()
        .start_address()
        .as_u64();
    let mut vaddr = VM::phys_to_virt(address);
    let ref mut context: EmulationContext = EmulationContext::new();
    let raw_stream = include_bytes!("ap");
    let ref mut stream = ByteStream::new(vaddr, raw_stream.len());

    PIC::reset();
    PIC::disable();

    for byte in raw_stream.iter() {
        unsafe {
            *(vaddr as *mut u8) = *byte;
        }
        vaddr += 1;
    }

    loop {
        decode_instruction(stream, context);
        if context.failed() {
            break;
        }
    }

    // Test 1
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::IO_INSTRUCTION as u16);
    assert_eq!(0x1 == regs.rax, true);
    assert_eq!(0x2 == regs.rbx, true);
    assert_eq!(0x3 == regs.rcx, true);
    let ioexit = IOExit::new();
    assert_eq!(ioexit.is_out(), true);
    assert_eq!(ioexit.size(), 1);
    assert_eq!(ioexit.is_string(), false);
    assert_eq!(ioexit.is_rep(), false);
    assert_eq!(ioexit.port(), 0xf4);
    assert_eq!(ioexit.is_op_immediate(), true);

    println!("[PASS ] simple register access");

    // Test 2
    VMCS::skip_instruction();
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::IO_INSTRUCTION as u16);
    assert_eq!(regs.rax, 0x2);
    let ioexit = IOExit::new();
    assert_eq!(ioexit.is_out(), true);
    assert_eq!(ioexit.size(), 1);
    assert_eq!(ioexit.is_string(), false);
    assert_eq!(ioexit.is_rep(), false);
    assert_eq!(ioexit.port(), 0x15);
    assert_eq!(ioexit.is_op_immediate(), true);

    println!("[PASS ] exit on intercepted I/O port");

    // Test 3
    unsafe { iobitmap.passthrough(0x15) };
    VMCS::skip_instruction();
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::IO_INSTRUCTION as u16);
    assert_eq!(regs.rax, 0x3);
    let ioexit = IOExit::new();
    assert_eq!(ioexit.is_out(), true);
    assert_eq!(ioexit.size(), 1);
    assert_eq!(ioexit.is_string(), false);
    assert_eq!(ioexit.is_rep(), false);
    assert_eq!(ioexit.port(), 0xf4);
    assert_eq!(ioexit.is_op_immediate(), true);

    println!("[PASS ] no exit on passthrough port");

    // Test 4
    VMCS::skip_instruction();
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::HLT as u16);
    assert_eq!(regs.rax, 0x4);

    println!("[PASS ] exit on HLT");

    // Test 5

    // disable hlt-exiting
    let mut vm_exec_control = VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.read();
    vm_exec_control &= !PrimaryVMExecControl::HLT_EXITING.bits();
    VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.write(vm_exec_control);

    // enable vmx preemption timer
    let mut pin_exec_control = VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.read();
    pin_exec_control |= PinVMExecControl::VMX_PREEMPTION_TIMER.bits();
    VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.write(pin_exec_control);

    VMCSField32Guest::VMX_PREEMPTION_TIMER_VALUE.write(0xfffff);

    VMCS::skip_instruction();
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::PREEMPTION_TIMER as u16);
    assert_eq!(regs.rax, 0x5);
    assert_eq!(VMCSField32Guest::ACTIVITY_STATE.read(), 0x1);

    println!("[PASS ] exit on preemption timer");

    // Test 6
    let mut vm_exec_control = VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.read();
    vm_exec_control |= PrimaryVMExecControl::HLT_EXITING.bits();
    VMCSField32Control::PROC_BASED_VM_EXEC_CONTROL.write(vm_exec_control);

    let mut pin_exec_control = VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.read();
    pin_exec_control &= !PinVMExecControl::VMX_PREEMPTION_TIMER.bits();
    VMCSField32Control::PIN_BASED_VM_EXEC_CONTROL.write(pin_exec_control);

    VMCSField32Guest::ACTIVITY_STATE.write(0x0);

    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::HLT as u16);
    assert_eq!(regs.rax, 0x6);

    println!("[PASS ] exit on HLT again");

    // Test 7
    VMCS::skip_instruction();
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::IO_INSTRUCTION as u16);
    assert_eq!(regs.rax, 0x7);
    let ioexit = IOExit::new();
    assert_eq!(ioexit.is_out(), true);
    assert_eq!(ioexit.size(), 1);
    assert_eq!(ioexit.is_string(), false);
    assert_eq!(ioexit.is_rep(), false);
    assert_eq!(ioexit.port(), 0xf4);
    assert_eq!(ioexit.is_op_immediate(), true);

    println!("[PASS ] exit on intercepted port");

    // Test 8
    VMCS::skip_instruction();
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::EPT_VIOLATION as u16);
    assert_eq!(regs.rbx, 0xdead);
    let eptexit = EPTViolationExit::new();
    assert_eq!(eptexit.violation_type(), EPTViolationType::DataRead);
    assert_eq!(eptexit.guest_physical_address, 0xdead);

    println!("[PASS ] exit on a read access");

    // Test 9
    VMCS::skip_instruction();
    regs.rbx = 0xbeef;
    VMCS::validate().expect("VMCS invalid");
    assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
    assert_eq!(VMCS::exit_reason(), VMXExitReason::EPT_VIOLATION as u16);
    assert_eq!(regs.rbx, 0xbeef);
    let eptexit = EPTViolationExit::new();
    assert_eq!(eptexit.violation_type(), EPTViolationType::DataWrite);
    assert_eq!(eptexit.guest_physical_address, 0xbeef);

    println!("[PASS ] exit on a write access");

    // Test 10
    for port in 0..0x13 {
        VMCS::skip_instruction();
        VMCS::validate().expect("VMCS invalid");
        assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
        assert_eq!(VMCS::exit_reason(), VMXExitReason::IO_INSTRUCTION as u16);
        let ioexit = IOExit::new();
        assert_eq!(ioexit.is_out(), true);
        assert_eq!(ioexit.size(), 1);
        assert_eq!(ioexit.is_string(), false);
        assert_eq!(ioexit.is_rep(), false);
        assert_eq!(ioexit.port(), port);
        assert_eq!(ioexit.is_op_immediate(), true);

        println!("[PASS ] exit on a I/O from interrupt handler number: 0x{:x}", port);
    }

    VMCS::skip_instruction();

    for port in 0..0x13 {
        inject_event(port, IntType::HardwareException);
        VMCS::validate().expect("VMCS invalid");
        assert_eq!(unsafe { vmcs.run(&mut regs) }, true);
        assert_eq!(VMCS::exit_reason(), VMXExitReason::IO_INSTRUCTION as u16);
        let ioexit = IOExit::new();
        assert_eq!(ioexit.is_out(), true);
        assert_eq!(ioexit.size(), 1);
        assert_eq!(ioexit.is_string(), false);
        assert_eq!(ioexit.is_rep(), false);
        assert_eq!(ioexit.port(), port as u16);
        assert_eq!(ioexit.is_op_immediate(), true);

        println!("[PASS ] injecting hardware exception: 0x{:x}", port);
    }

    return true;
}
