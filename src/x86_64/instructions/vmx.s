.equ RDI, 0x00
.equ RAX, 0x08
.equ RBX, 0x10
.equ RCX, 0x18
.equ RDX, 0x20
.equ RSI, 0x28
.equ RBP, 0x30
.equ R8,  0x38
.equ R9,  0x40
.equ R10, 0x48
.equ R11, 0x50
.equ R12, 0x58
.equ R13, 0x60
.equ R14, 0x68
.equ R15, 0x70

.macro restore_host_regs
    pop %rdi
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
.endmacro

.macro vmx instruction
.global vmx_\instruction
vmx_\instruction:
    /// save host state
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    /// &guest_regs, push last. It is used in guest save later.
    push %rdi;

    /// set return stack
    mov $0x00006c14, %rax
    vmwrite %rsp, %rax

    /// restore guest state without affecting the result of cmp
    mov RAX(%rdi), %rax
    mov RBX(%rdi), %rbx
    mov RCX(%rdi), %rcx
    mov RDX(%rdi), %rdx
    mov RSI(%rdi), %rsi
    mov RBP(%rdi), %rbp
    mov R8(%rdi),  %r8
    mov R9(%rdi),  %r9
    mov R10(%rdi), %r10
    mov R11(%rdi), %r11
    mov R12(%rdi), %r12
    mov R13(%rdi), %r13
    mov R14(%rdi), %r14
    mov R15(%rdi), %r15

    /// Now kill %rsi which contains the guest_regs.
    mov RDI(%rdi), %rdi

    \instruction

    /// If we are here, vmlaunch/vmresume failed
    restore_host_regs
    xor %rax, %rax
    retq
.endmacro

.code64

.global vmx_return

vmx vmlaunch
vmx vmresume

vmx_return:
    /// save it for now
    push %rdi

    /// get the guest_regs register
    mov 0x8(%rsp), %rdi

    /// save guest state
    mov %rax, RAX(%rdi)
    mov %rbx, RBX(%rdi)
    mov %rcx, RCX(%rdi)
    mov %rdx, RDX(%rdi)
    mov %rsi, RSI(%rdi)
    mov %rbp, RBP(%rdi)
    mov %r8,  R8(%rdi)
    mov %r9,  R9(%rdi)
    mov %r10, R10(%rdi)
    mov %r11, R11(%rdi)
    mov %r12, R12(%rdi)
    mov %r13, R13(%rdi)
    mov %r14, R14(%rdi)
    mov %r15, R15(%rdi)
    mov 0x0(%rsp), %rax /// get guest %rdi from stack
    mov %rax, RDI(%rdi)

    add $0x8, %rsp
    restore_host_regs

    /// VMLAUNCH/VMRESUME was successful
    mov $1, %rax
    retq;