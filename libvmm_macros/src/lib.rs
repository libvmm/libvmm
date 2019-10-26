extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::parse::{Parse, ParseStream};
use syn::{ItemEnum, Visibility, Expr, Error};
use syn::{Ident, Token, braced, parse_macro_input, LitStr, LitInt};

struct VMCSFieldArguments {
    width: u64,
    access: LitStr,
}

impl Parse for VMCSFieldArguments {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        let width_lit: LitInt = input.parse()?;
        input.parse::<Token![,]>()?;
        let access: LitStr = input.parse()?;
        let width: u64 = width_lit.base10_parse().expect("Invalid width");

        if width != 16 && width != 32 && width != 64 {
            panic!("width can only be \"16\", \"32\", and \"64\"");
        }

        if access.value().as_str() != "R" && access.value().as_str() != "RW" {
            panic!("access can only be \"R\" or \"RW\"");
        }

        Ok(VMCSFieldArguments {
            width,
            access,
        })
    }
}

///
/// Macro usage:
///
/// #[vmcs_field({16, 32, 64}, {"R", "RW"})
///
/// This can only be used for "enums"
#[proc_macro_attribute]
pub fn vmcs_access(args: TokenStream, input: TokenStream) -> TokenStream {
    let VMCSFieldArguments {
        width,
        access,
    } = parse_macro_input!(args as VMCSFieldArguments);

    let enum_stream = parse_macro_input!(input as ItemEnum);
    let name = enum_stream.ident.clone();
    let vm_size = format_ident!("u{}", width);

    let read_fn = quote! {
        pub fn read(&self) -> #vm_size {
            let mut value: u64;
            unsafe { asm!("vmread $1, $0": "=r" (value): "r" (*self as u64)) };
            value as #vm_size
        }
    };

    let write_fn = quote! {
        pub fn write(&self, value: #vm_size) {
            unsafe { asm!("vmwrite $0, $1":: "r" (value as u64), "r" (*self as u64)) };
        }
    };

    if access.value().as_str() == "R" {
        return TokenStream::from(
            quote! {
                #enum_stream

                impl #name {
                    #read_fn
                }
            });
    } else {
        return TokenStream::from(
            quote! {
                #enum_stream

                impl #name {
                    #read_fn
                    #write_fn
                }
            });
    }
}

struct PageTable {
    visibility: Visibility,
    table: Ident,
    valid_flags: Expr,
    valid_huge_flags: Expr,
    huge_flags: Expr,
    normal_shift: Expr,
    huge_shift: Expr,
    index_shift: Expr,
}

///
/// Format of special syntax:
///
/// page_table! (
///     pub struct <table> {
///         valid_flags: <valid_bits>,
///         valid_huge_flags: <valid_huge_flags>,
///         huge_flags: <huge_flags>,
///         normal_shift: <normal_shift>,
///         huge_shift: <huge_shift>,
///         index_shift: <index_shift>,
///     }
/// )
///
impl Parse for PageTable {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        let visibility: Visibility = input.parse()?;
        input.parse::<Token![struct]>()?;
        let table: Ident = input.parse()?;

        let content;
        braced!(content in input);

        let mut valid_flags: Option<Expr> = None;
        let mut valid_huge_flags: Option<Expr> = None;
        let mut huge_flags: Option<Expr> = None;
        let mut normal_shift: Option<Expr> = None;
        let mut huge_shift: Option<Expr> = None;
        let mut index_shift: Option<Expr> = None;

        loop {
            if content.is_empty() {
                break;
            }

            let ident: Ident = content.parse()?;
            content.parse::<Token![:]>()?;

            match ident.to_string().as_str() {
                "valid_flags" => { valid_flags.replace(content.parse()?); },
                "valid_huge_flags" => { valid_huge_flags.replace(content.parse()?); },
                "huge_flags" => { huge_flags.replace(content.parse()?); },
                "normal_shift" => { normal_shift.replace(content.parse()?); },
                "huge_shift" => { huge_shift.replace(content.parse()?); },
                "index_shift" => { index_shift.replace(content.parse()?); },
                _ => panic!("wrong identifier"),
            }

            content.parse::<Token![,]>()?;

            if content.is_empty() {
                break;
            }

        }

        Ok(PageTable {
            visibility: visibility,
            table: table,
            valid_flags: valid_flags.expect("missing 'valid_flags' attribute"),
            valid_huge_flags: valid_huge_flags.expect("missing 'valid_huge_flags' attribute"),
            huge_flags: huge_flags.expect("missing 'huge_flags' attribute"),
            normal_shift: normal_shift.expect("missing 'normal_shift' attribute"),
            huge_shift: huge_shift.expect("missing 'huge_shift' attribute"),
            index_shift: index_shift.expect("missing 'index_shift' attribute"),
        })
    }
}

#[proc_macro]
pub fn construct_pt_types(input: TokenStream) -> TokenStream {
    let PageTable {
        visibility,
        table,
        valid_flags,
        valid_huge_flags,
        huge_flags,
        normal_shift,
        huge_shift,
        index_shift,
    } = parse_macro_input!(input as PageTable);

    let entry_name = format_ident!("{}Entry", table);
    //let convert_macro_name = format_ident!("cast_to_{}", table);

    let output = quote! {
        #[repr(packed)]
        #[derive(Debug, Clone, Copy)]
        #visibility struct #entry_name(u64);

        #[repr(packed)]
        #visibility struct #table {
            entries: [#entry_name; 512],
        }

        impl core::ops::Index<u64> for #table {
            type Output = #entry_name;

            fn index(&self, address: u64) -> &Self::Output {
                let index = ((address) >> (#index_shift)) & 0x1ff;
                &self.entries[index as usize]
            }
        }

        impl core::ops::IndexMut<u64> for #table {
            fn index_mut(&mut self, address: u64) -> &mut Self::Output {
                let index = ((address) >> (#index_shift)) & 0x1ff;
                &mut self.entries[index as usize]
            }
        }

/* -- "[E0658]: procedural macros cannot expand to macro definitions"
        #[macro_export]
        macro_rules! #convert_macro_name {
            ($x:expr) => {
                unsafe_cast!($x => &mut #table)
            }
        }
*/

        impl #entry_name {
            pub fn new(address: u64, flags: u64) -> Option<Self> {
                let mut shift: u8 = #normal_shift;
                let mut valid: u64 = #valid_flags;

                if #huge_flags != 0 && ((flags & #huge_flags) == #huge_flags) {
                    valid |= #valid_huge_flags;
                    shift = #huge_shift;
                }

                let aligned = ((address & ((1 << shift) - 1)) == 0);
                if !aligned || ((valid & flags) != flags) {
                    return None;
                }

                Some(Self(address | flags))
            }

            pub fn raw(&self) -> u64 {
                self.0
            }

            pub fn huge(&self) -> bool {
                (self.0 & #huge_flags) == #huge_flags
            }
        }
    };

    TokenStream::from(output)
}