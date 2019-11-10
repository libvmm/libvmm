.code16
start:

.macro int_handler handler offset
    .org \offset, 0x00
    .word \handler - start
    .word 0x0
.endm

// 0x00
int_handler divide_by_zero      0x00
// 0x01
int_handler reserved            0x04
// 0x02
int_handler nmi                 0x08
// 0x03
int_handler breakpoint          0x0c
// 0x04
int_handler overflow            0x10
// 0x05
int_handler bound               0x14
// 0x06
int_handler invalid_opcode      0x18
// 0x07
int_handler unavailable_dev     0x1c
// 0x08
int_handler double_fault        0x20
// 0x09
int_handler coproc              0x24
// 0x0a
int_handler invalid_tss         0x28
// 0x0b
int_handler segment_not_present 0x2c
// 0x0c
int_handler stack_segment_fault 0x30
// 0x0d
int_handler gp_fault            0x34
// 0x0e
int_handler page_fault          0x38
// 0x0f
int_handler x87_fpu_error       0x3c
// 0x10
int_handler alignment_check     0x40
// 0x11
int_handler machine_check       0x44
// 0x12
int_handler simd_fpu_exception  0x48

// Offset 1 KiB
.org 0x400
divide_by_zero:
    outb %al, $0x00
    iret

reserved:
    outb %al, $0x01
    iret

nmi:
    outb %al, $0x02
    iret

breakpoint:
    outb %al, $0x03
    iret

overflow:
    outb %al, $0x04
    iret

bound:
    outb %al, $0x05
    iret

invalid_opcode:
    outb %al, $0x06
    iret

unavailable_dev:
    outb %al, $0x07
    iret

double_fault:
    outb %al, $0x08
    iret

coproc:
    outb %al, $0x09
    iret

invalid_tss:
    outb %al, $0x0a
    iret

segment_not_present:
    outb %al, $0x0b
    iret

stack_segment_fault:
    outb %al, $0x0c
    iret

gp_fault:
    outb %al, $0x0d
    iret

page_fault:
    outb %al, $0x0e
    iret

x87_fpu_error:
    outb %al, $0x0f
    iret

alignment_check:
    outb %al, $0x10
    iret

machine_check:
    outb %al, $0x11

simd_fpu_exception:
    outb %al, $0x12
    iret

// Offset 3 KiB
.org 0x800
main:
    mov $0x1, %al
    mov $0x2, %bl
    mov $0x3, %cl

    // Test 1 - evaluate now!
    outb %al, $0xf4

    // Test 2 - evaluate now!
    mov $0x2, %al
    outb %al, $0x15

    // should not exit
    outb %al, $0x15

    // Test 3 - evaluate now!
    mov $0x3, %al
    outb %al, $0xf4

    // Test 4 - evaluate now!
    mov $0x4, %al
    hlt

    // Test 5 - evaluate now!
    mov $0x5, %al
    hlt

    // Test 6 - evaluate now!
    mov $0x6, %al
    hlt

    // Test 7 - evaluate now!
    mov $0x7, %al
    outb %al, $0xf4

    // Test 8 - evaluate now!
    mov $0xdead, %bx
    mov (%bx), %bx

    // Test 9 - evaluate now!
    mov %ax, (%bx)

    // Test 10 - evaluate now!
    int $0x0
    int $0x1
    int $0x2
    int $0x3
    int $0x4
    int $0x5
    int $0x6
    int $0x7
    int $0x8
    int $0x9
    int $0xa
    int $0xb
    int $0xc
    int $0xd
    int $0xe
    int $0xf
    int $0x10
    int $0x11
    int $0x12

.org 0xc00
stack:
    .fill 1024, 0x0
.org 0x1000 - 1