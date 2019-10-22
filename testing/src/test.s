.code16
    mov $0x1, %al
    mov $0x2, %bl
    mov $0x3, %cl
    mov $0x4, %dl

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
    outb %al, $0xf4