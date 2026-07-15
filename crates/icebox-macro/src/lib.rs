//! `#[module(...)]` attribute macro for ICEBOX modules.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Expr, ExprLit, Fields, Lit, Meta,
    Token,
};
use syn::punctuated::Punctuated;

#[proc_macro_attribute]
pub fn module(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with Punctuated::<Meta, Token![,]>::parse_terminated);
    let mut input = parse_macro_input!(item as DeriveInput);
    let name = input.ident.clone();
    let opts_name = format_ident!("{}Options", name);

    let mut map: HashMap<String, String> = HashMap::new();
    for n in &args {
        if let Meta::NameValue(nv) = n {
            if let Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) = &nv.value {
                let k = nv.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
                map.insert(k, s.value());
            }
        }
    }

    if !map.contains_key("name") || !map.contains_key("kind") {
        return quote! {
            compile_error!("`#[module]` requires at least `name = \"...\"` and `kind = \"...\"`");
        }
        .into();
    }

    let m_name = map.get("name").unwrap();
    let m_desc = map.get("description").cloned().unwrap_or_default();
    let m_author = map.get("author").cloned().unwrap_or_default();
    let m_kind = map.get("kind").unwrap();
    let kind_ident = format_ident!("{}", m_kind);

    // `capabilities` is optional; when omitted the kind supplies a default set.
    let caps_expr = if let Some(cs) = map.get("capabilities") {
        let idents: Vec<proc_macro2::TokenStream> = cs
            .split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| {
                let id = format_ident!("{}", t);
                quote! { icebox_core::module::Capability::#id }
            })
            .collect();
        quote! { vec![ #(#idents),* ] }
    } else {
        quote! { icebox_core::module::Capability::from_kind(icebox_core::module::ModuleKind::#kind_ident) }
    };

    // `impact` / `intent` are optional authoritive overrides; the literal must
    // name a `RiskLevel` / `Intent` variant.
    let impact_expr = match map.get("impact") {
        Some(s) => {
            let id = format_ident!("{}", s);
            quote! { Some(icebox_core::safety::RiskLevel::#id) }
        }
        None => quote! { None },
    };
    let intent_expr = match map.get("intent") {
        Some(s) => {
            let id = format_ident!("{}", s);
            quote! { Some(icebox_core::module::Intent::#id) }
        }
        None => quote! { None },
    };

    let mut field_defs = Vec::new();
    let mut opt_meta: Vec<(String, syn::Ident, syn::Type, bool)> = Vec::new();
    if let Data::Struct(s) = &mut input.data {
        if let Fields::Named(named) = &mut s.fields {
            for f in named.named.iter_mut() {
                let fname = f.ident.clone().unwrap();
                let fty = f.ty.clone();
                let mut required = false;
                let mut kept: Vec<syn::Attribute> = Vec::new();
                for a in &f.attrs {
                    if a.path().is_ident("option") {
                        if let Ok(pair) =
                            a.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                        {
                            for n in pair {
                                match n {
                                    Meta::Path(p) => {
                                        if p.is_ident("required") {
                                            required = true;
                                        }
                                    }
                                    Meta::NameValue(nv) if nv.path.is_ident("required") => {
                                        match &nv.value {
                                            Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => {
                                                required = s.value() == "true";
                                            }
                                            Expr::Lit(ExprLit { lit: Lit::Bool(b), .. }) => {
                                                required = b.value;
                                            }
                                            _ => {}
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    } else {
                        kept.push(a.clone());
                    }
                }
                f.attrs = kept;
                field_defs.push(quote! { pub #fname: #fty });
                opt_meta.push((fname.to_string(), fname, fty, required));
            }
        }
    }

    let opts_fields = &field_defs;
    let mut validate_arms = Vec::new();
    let mut set_arms = Vec::new();
    for (fstr, fident, fty, required) in &opt_meta {
        let fstr_lit = fstr.clone();
        let parse_expr = match ty_to_kind(fty) {
            "string" => quote! { self.#fident = value.to_string(); },
            "bool" => quote! { self.#fident = matches!(value, "true" | "1"); },
            "ip" => quote! { self.#fident = value.parse().map_err(|_| icebox_core::ModuleError::Parse(#fstr_lit.into()))?; },
            _ => quote! { self.#fident = value.parse().map_err(|_| icebox_core::ModuleError::Parse(#fstr_lit.into()))?; },
        };
        set_arms.push(quote! { #fstr_lit => { #parse_expr } });
        if *required {
            if ty_to_kind(fty) == "string" {
                validate_arms.push(quote! {
                    if self.#fident.is_empty() {
                        return Err(icebox_core::ModuleError::MissingOption(#fstr_lit.into()));
                    }
                });
            } else {
                validate_arms.push(quote! {
                    {
                        let __dflt: #fty = ::core::default::Default::default();
                        if self.#fident == __dflt {
                            return Err(icebox_core::ModuleError::MissingOption(#fstr_lit.into()));
                        }
                    }
                });
            }
        }
    }

    let opts_struct = quote! {
        #[derive(::core::fmt::Debug, ::core::default::Default, ::core::clone::Clone, ::serde::Serialize)]
        pub struct #opts_name {
            #(#opts_fields),*
        }
    };
    let opts_impl = quote! {
        impl #opts_name {
            pub fn validate(&self) -> Result<(), icebox_core::ModuleError> {
                #(#validate_arms)*
                Ok(())
            }
            pub fn set(&mut self, name: &str, value: &str) -> Result<(), icebox_core::ModuleError> {
                match name {
                    #(#set_arms,)*
                    _ => return Err(icebox_core::ModuleError::Other(format!("unknown option: {}", name))),
                }
                Ok(())
            }
        }
    };

    let info_impl = quote! {
        impl #name {
            pub fn build_info() -> icebox_core::ModuleInfo {
                icebox_core::ModuleInfo {
                    name: #m_name.into(),
                    description: #m_desc.into(),
                    author: #m_author.into(),
                    kind: icebox_core::ModuleKind::#kind_ident,
                    capabilities: #caps_expr,
                    impact: #impact_expr,
                    intent: #intent_expr,
                }
            }
        }
    };

    let base = name.to_string().to_lowercase();
    let make_fn = format_ident!("__icebox_make_{}", base);
    let info_fn = format_ident!("__icebox_info_{}", base);
    let entry = format_ident!("__ICEBOX_ENTRY_{}", base);

    let make_fn_def = quote! { fn #make_fn() -> Box<dyn icebox_core::Module> { Box::new(#name::default()) } };
    let info_fn_def = quote! { fn #info_fn() -> icebox_core::ModuleInfo { #name::build_info() } };
    let linkme_static = quote! {
        #[::linkme::distributed_slice(crate::MODULE_REGISTRY)]
        #[linkme(crate = linkme)]
        static #entry: icebox_core::ModuleEntry = icebox_core::ModuleEntry {
            info: #info_fn,
            make: #make_fn,
        };
    };

    // strip the #[module] attr, inject Default/Clone/Debug on the user struct
    input.attrs.retain(|a| !a.path().is_ident("module"));
    input
        .attrs
        .push(parse_quote!(#[derive(::core::default::Default, ::core::clone::Clone, ::core::fmt::Debug)]));

    let expanded = quote! {
        #input
        #opts_struct
        #opts_impl
        #info_impl
        #make_fn_def
        #info_fn_def
        #linkme_static
    };
    expanded.into()
}

fn ty_to_kind(ty: &syn::Type) -> &'static str {
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return match seg.ident.to_string().as_str() {
                "String" => "string",
                "u16" | "u32" | "u64" | "i32" | "i64" | "usize" => "int",
                "bool" => "bool",
                "IpAddr" => "ip",
                _ => "string",
            };
        }
    }
    "string"
}
