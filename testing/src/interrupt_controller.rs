pub trait InterruptController {
    fn enable();
    fn disable();
    fn reset();
    fn eoi(irq: u32);
    fn spurious_irq() -> u32;
    fn mask(irq: u32);
    fn unmask(irq: u32);
}