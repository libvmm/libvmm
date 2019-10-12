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
        pub unsafe fn read(&self) -> #vm_size {
            let mut value: u64;
            asm!("vmread $1, $0": "=r" (value): "r" (*self as u64));
            value as #vm_size
        }
    };

    let write_fn = quote! {
        pub unsafe fn write(&self, value: #vm_size) {
            asm!("vmwrite $0, $1":: "r" (value as u64), "r" (*self as u64));
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