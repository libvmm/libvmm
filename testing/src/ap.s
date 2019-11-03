.section .ap-bootstrap, "awx"
.intel_syntax noprefix
.code16

    # zero segment registers
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    # clear the direction flag (e.g. go forward in memory when using
    # instructions like lodsb)
    cld

    # initialize stack
    mov sp, (0x7c00 - 0x16)

    # enable A20-Line via IO-Port 92, might not work on all motherboards
    in al, 0x92
    test al, 2
    jnz 1f
    or al, 2
    and al, 0xFE
    out 0x92, al
1:

    # enter protected mode
    cli
    lgdt [gdt32info]
    mov eax, cr0
    or al, 1    # set protected mode bit
    mov cr0, eax

    push 0x8
    lea eax, [switch_pm_cs]
    push eax
    retf

.code32
switch_pm_cs:
    mov bx, 0x10
    mov ds, bx # set data segment
    mov es, bx # set extra segment
    #mov ss, bx # set stack segment

    lidt zero_idt         # Load a zero length IDT so that any NMI causes a triple fault.

    # enter long mode

    # enable paging
    # Write back cache and add a memory fence. I'm not sure if this is
    # necessary, but better be on the safe side.
    wbinvd
    mfence

    # load the identity page table created by the BSP
    lea eax, [_p4]
    mov cr3, eax

    # enable PAE-flag in cr4 (Physical Address Extension)
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    # set the long mode bit in the EFER MSR (model specific register)
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    # enable paging in the cr0 register
    mov eax, cr0
    and eax, 0x1fffffff     # disable caching / write-through
    or eax, (1 << 31)       # enable-paging
    or eax, (1 << 16)       # write-protect
    mov cr0, eax

    # load 64bit gdt
    lgdt gdt_64_pointer                # Load GDT.Pointer defined below.

    # jump to long mode
    push 0x8
    lea eax, [start_ap]
    push eax
    retf # Load CS with 64 bit segment and flush the instruction cache

.code64
final_stage:
    mov eax, 0xdeadbeef
1:  jmp 1b