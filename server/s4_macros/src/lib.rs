//! S4 Authentication Macros
//!
//! This crate provides procedural macros for Rocket routes that automatically
//! extract authentication keys from requests (query params, headers, or cookies).
//!
//! # Usage
//!
//! ```rust,ignore
//! use s4_macros::authenticated;
//!
//! #[authenticated::get("/my_route")]
//! async fn my_handler(auth_key: String, pool: &State<DbPool>) -> String {
//!     // auth_key is automatically extracted from the request
//!     format!("Authenticated with key: {}", auth_key)
//! }
//! ```

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{FnArg, ItemFn, Pat, PatIdent, ReturnType, parse_macro_input};

/// Helper struct to parse route attributes
struct RouteArgs {
    path: String,
    rest: Option<proc_macro2::TokenStream>,
}

impl syn::parse::Parse for RouteArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let path: syn::LitStr = input.parse()?;
        let rest = if input.peek(syn::Token![,]) {
            let _: syn::Token![,] = input.parse()?;
            let rest: proc_macro2::TokenStream = input.parse()?;
            Some(rest)
        } else {
            None
        };
        Ok(RouteArgs {
            path: path.value(),
            rest,
        })
    }
}

/// Generates the wrapper function and inner function for authenticated routes
fn generate_authenticated_route(method: &str, attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as RouteArgs);
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let fn_asyncness = &input_fn.sig.asyncness;
    let fn_block = &input_fn.block;
    let fn_generics = &input_fn.sig.generics;
    let fn_where = &input_fn.sig.generics.where_clause;

    // Extract return type
    let return_type = match &input_fn.sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => quote! { #ty },
    };

    // Separate auth_key from other params
    let mut has_auth_key = false;
    let mut other_params: Punctuated<FnArg, Comma> = Punctuated::new();
    let mut inner_call_args: Vec<proc_macro2::TokenStream> = Vec::new();

    for param in input_fn.sig.inputs.iter() {
        match param {
            FnArg::Typed(pat_type) => {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                    if ident == "auth_key" {
                        has_auth_key = true;
                        // auth_key will be generated from the extraction
                        inner_call_args.push(quote! { __auth_key });
                    } else {
                        other_params.push(param.clone());
                        inner_call_args.push(quote! { #ident });
                    }
                } else {
                    other_params.push(param.clone());
                }
            }
            FnArg::Receiver(_) => {
                other_params.push(param.clone());
            }
        }
    }

    if !has_auth_key {
        // If no auth_key parameter, just pass through to regular rocket macro
        let method_ident = format_ident!("{}", method);
        let path = &args.path;
        let rest = args.rest.map(|r| quote! { , #r }).unwrap_or_default();

        return TokenStream::from(quote! {
            #[rocket::#method_ident(#path #rest)]
            #input_fn
        });
    }

    // Generate the inner function name
    let inner_fn_name = format_ident!("{}_inner", fn_name);

    // Build rocket attribute
    let method_ident = format_ident!("{}", method);

    // Modify path to include ?<key> for query param extraction if not already present
    let path = {
        let original_path = &args.path;
        if original_path.contains("?") {
            // Already has query params, append &<key>
            if original_path.contains("<key>") {
                original_path.clone()
            } else {
                format!("{}&<key>", original_path)
            }
        } else {
            // No query params yet, add ?<key>
            format!("{}?<key>", original_path)
        }
    };
    let rest = args.rest.map(|r| quote! { , #r }).unwrap_or_default();

    // Check if we already have a key query param
    let has_key_param = other_params.iter().any(|p| {
        if let FnArg::Typed(pat_type) = p {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                return ident == "key";
            }
        }
        false
    });

    // Check if we already have auth_header param
    let has_auth_header_param = other_params.iter().any(|p| {
        if let FnArg::Typed(pat_type) = p {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                return ident == "auth_header";
            }
        }
        false
    });

    // Check if we already have cookies param
    let has_cookies_param = other_params.iter().any(|p| {
        if let FnArg::Typed(pat_type) = p {
            if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                return ident == "cookies";
            }
        }
        false
    });

    // Add required params for auth extraction if not present
    let key_param = if !has_key_param {
        quote! { key: Option<String>, }
    } else {
        quote! {}
    };

    let auth_header_param = if !has_auth_header_param {
        quote! { auth_header: crate::utils::complex::AuthHeader, }
    } else {
        quote! {}
    };

    let cookies_param = if !has_cookies_param {
        quote! { cookies: &rocket::http::CookieJar<'_>, }
    } else {
        quote! {}
    };

    // Build inner call args for non-auth params
    let inner_args: Vec<proc_macro2::TokenStream> = other_params
        .iter()
        .filter_map(|p| {
            if let FnArg::Typed(pat_type) = p {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                    // Skip the auth extraction params from inner call
                    if ident == "key" || ident == "auth_header" || ident == "cookies" {
                        return None;
                    }
                    return Some(quote! { #ident });
                }
            }
            None
        })
        .collect();

    // Filter out auth extraction params from inner function params
    let inner_fn_params: Punctuated<FnArg, Comma> = other_params
        .iter()
        .filter(|p| {
            if let FnArg::Typed(pat_type) = p {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat {
                    return ident != "key" && ident != "auth_header" && ident != "cookies";
                }
            }
            true
        })
        .cloned()
        .collect();

    // Build the final inner call arguments
    let final_inner_args = {
        let mut args = vec![quote! { __auth_key }];
        args.extend(inner_args);
        args
    };

    let output = quote! {
        #[rocket::#method_ident(#path #rest)]
        #fn_vis #fn_asyncness fn #fn_name #fn_generics (
            #key_param
            #auth_header_param
            #cookies_param
            #other_params
        ) -> #return_type
        #fn_where
        {
            let __auth_key = crate::utils::auth::get_auth_key(key, &auth_header, cookies)
                .unwrap_or_else(|| String::new());

            #inner_fn_name(#(#final_inner_args),*).await
        }

        #[allow(dead_code)]
        #fn_asyncness fn #inner_fn_name #fn_generics (
            auth_key: String,
            #inner_fn_params
        ) -> #return_type
        #fn_where
        #fn_block
    };

    TokenStream::from(output)
}

/// Authenticated GET route
///
/// Automatically extracts the auth key from query params, Authorization header, or cookies.
/// The `auth_key` parameter in your function will be populated with the extracted key,
/// or an empty string if no key is found.
///
/// # Example
///
/// ```rust,ignore
/// #[authenticated::get("/protected")]
/// async fn protected_route(auth_key: String, pool: &State<DbPool>) -> String {
///     if auth_key.is_empty() {
///         return "Not authenticated".to_string();
///     }
///     "Authenticated!".to_string()
/// }
/// ```
#[proc_macro_attribute]
pub fn get(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("get", attr, item)
}

/// Authenticated POST route
#[proc_macro_attribute]
pub fn post(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("post", attr, item)
}

/// Authenticated PUT route
#[proc_macro_attribute]
pub fn put(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("put", attr, item)
}

/// Authenticated DELETE route
#[proc_macro_attribute]
pub fn delete(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("delete", attr, item)
}

/// Authenticated PATCH route
#[proc_macro_attribute]
pub fn patch(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("patch", attr, item)
}

/// Authenticated HEAD route
#[proc_macro_attribute]
pub fn head(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("head", attr, item)
}

/// Authenticated OPTIONS route
#[proc_macro_attribute]
pub fn options(attr: TokenStream, item: TokenStream) -> TokenStream {
    generate_authenticated_route("options", attr, item)
}
