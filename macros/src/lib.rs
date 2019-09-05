extern crate proc_macro;
use proc_macro::TokenStream;
use syn::{parse_macro_input, parse_quote, Block, ImplItem, ImplItemMethod, Item, ItemImpl, Stmt};
use quote::quote;
use std::collections::HashSet;

/// A macro for implementing the storage trait.  This provides default mock methods for the trait,
/// but provides any `impl` block to override the defaults with its own implementation.
///
/// # Example
///
/// ```
/// struct AlwaysReturnsSixStorage;
/// #[storage_trait_impl]
/// impl Storage for AlwaysReturnsSixStorage {
///     fn get_int(&self, _key: String) -> Option<usize> { Some(6) }
/// }
///
/// fn main() {
///     assert_eq!(AlwaysReturnsSixStorage.get_int("test".to_string()), Some(6));
/// }
/// ```
#[proc_macro_attribute]
pub fn storage_trait_impl(_: TokenStream, input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as ItemImpl);

    let mut methods = HashSet::new();
    for item in &input.items {
        if let ImplItem::Method(method) = item {
            methods.insert(method.sig.ident.to_string());
        }
    }

    let default_impl: Block = parse_quote!({
        fn get_int(&self, _key: String) -> Option<usize> { Some(5) }
        fn set_int(&self, _key: String, _value: usize) {}
        fn get_string(&self, _key: String) -> Option<String> { Some(String::from("test")) }
        fn set_string(&self, _key: String, _value: String) {}
        fn get_bool(&self, key: String) -> Option<bool> {
            if key == String::from("http_nowhere_on") {
                Some(false)
            } else {
                Some(true)
            }
        }
        fn set_bool(&self, _key: String, _value: bool) {}
    });

    for item in default_impl.stmts {
        if let Stmt::Item(Item::Fn(item_fn)) = item {
            if !methods.contains(&item_fn.sig.ident.to_string()) {
                let method: ImplItemMethod = parse_quote! {
                    #item_fn
                };
                input.items.push(ImplItem::Method(method));
            }
        }
    }

    let res = quote! {
        #input
    };
    res.into()
}
