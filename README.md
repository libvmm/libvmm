# Library VMM

Experimenting with building library VMM in Rust. Unclear what this will turn out to be.

## License

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## Todo

- [ ] Instruction emulation.
- [ ] Create a library OS to use it for testing.
- [ ] Add support for request-interrupt-window.
- [ ] Add support for Interrupt on entry settings.
- [ ] Add support for managing IOMMU page tables.
- [ ] Add support for hardware posted interrupt.
- [ ] Add support for APICv.
- [ ] Add support for SVM.
- [ ] Add better support for non-root guest mode code.
- [ ] Extend the VMCS validation checks in (${}/src/x86_64/instructions/vmcs.rs).
  - [ ] 26.2 VMX controls and host state.
    - [ ] 26.2.1 VMX controls.
      - [ ] 26.2.1.2 VM Exit control validation.
      - [ ] 26.2.1.3 VM Entry control validation.
    - [ ] 26.2.2 Host controls and MSRs.
    - [ ] 26.2.3 Host segment and descriptor tables.
    - [ ] 26.2.4 Address space size.
  - [ ] 26.3 Guest state.
