use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, punctuated::Punctuated, Attribute, Data, DeriveInput, Fields,
    GenericArgument, Meta, PathArguments, Token, Type, TypePath,
};

#[proc_macro_derive(Patch, attributes(patch))]
pub fn derive_patch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match derive_patch_impl(input) {
        Ok(expanded) => expanded,
        Err(err) => err.to_compile_error().into(),
    }
}

fn derive_patch_impl(input: DeriveInput) -> syn::Result<TokenStream> {
    let DeriveInput {
        ident: struct_name,
        vis,
        attrs,
        data,
        generics,
        ..
    } = input;

    ensure_no_generics(&generics)?;

    let nested_all = has_nested_all_attr(&attrs)?;
    let fields = extract_named_fields(data, &struct_name)?;
    let patch_name = format_ident!("{}Patch", struct_name);

    let mut patch_fields = Vec::new();
    let mut apply_stmts = Vec::new();

    for field in fields {
        let field_ident = match field.ident {
            Some(ident) => ident,
            None => return Err(syn::Error::new_spanned(&field, "expected named field")),
        };
        let field_ty = field.ty;

        let nested = has_nested_attr(&field.attrs)? || nested_all;
        let serde_attrs = serde_field_attrs(&field.attrs);
        let option_inner = option_inner_type(&field_ty);

        let mut extra_serde_attrs: Vec<Attribute> = Vec::new();
        if option_inner.is_some() {
            extra_serde_attrs.push(syn::parse_quote!(
                #[serde(
                    default,
                    deserialize_with = "common_utils::config_patch::deserialize_option_option"
                )]
            ));
        }

        let (patch_field_ty, apply_stmt) = match (option_inner, nested) {
            (Some(inner_ty), true) => {
                let inner_patch_ty = patch_type(inner_ty)?;
                (
                    quote! { ::core::option::Option<::core::option::Option<#inner_patch_ty>> },
                    quote! {
                        ::common_utils::config_patch::apply_optional_patch(
                            &mut self.#field_ident,
                            patch.#field_ident,
                        );
                    },
                )
            }
            (Some(inner_ty), false) => (
                quote! { ::core::option::Option<::core::option::Option<#inner_ty>> },
                quote! {
                    ::common_utils::config_patch::apply_option_value(
                        &mut self.#field_ident,
                        patch.#field_ident,
                    );
                },
            ),
            (None, true) => {
                let nested_patch_ty = patch_type(&field_ty)?;
                (
                    quote! { ::core::option::Option<#nested_patch_ty> },
                    quote! {
                        ::common_utils::config_patch::apply_nested(
                            &mut self.#field_ident,
                            patch.#field_ident,
                        );
                    },
                )
            }
            (None, false) => (
                quote! { ::core::option::Option<#field_ty> },
                quote! {
                    ::common_utils::config_patch::apply_replace(
                        &mut self.#field_ident,
                        patch.#field_ident,
                    );
                },
            ),
        };

        patch_fields.push(quote! {
            #(#serde_attrs)*
            #(#extra_serde_attrs)*
            pub #field_ident: #patch_field_ty
        });
        apply_stmts.push(apply_stmt);
    }

    Ok(quote! {
        #[derive(Debug, Default, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(default)]
        #vis struct #patch_name {
            #(#patch_fields,)*
        }

        impl ::common_utils::config_patch::Patch<#patch_name> for #struct_name {
            fn apply(&mut self, patch: #patch_name) {
                #(#apply_stmts)*
            }
        }
    }
    .into())
}

fn ensure_no_generics(generics: &syn::Generics) -> syn::Result<()> {
    let has_generics = !generics.params.is_empty();
    match has_generics {
        true => Err(syn::Error::new_spanned(
            generics,
            "Patch derive does not support generics",
        )),
        false => Ok(()),
    }
}

fn extract_named_fields(
    data: Data,
    struct_name: &syn::Ident,
) -> syn::Result<Punctuated<syn::Field, Token![,]>> {
    match data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => Ok(fields.named),
            other => Err(syn::Error::new_spanned(
                other,
                "Patch derive only supports structs with named fields",
            )),
        },
        _ => Err(syn::Error::new_spanned(
            struct_name,
            "Patch derive only supports structs",
        )),
    }
}

fn has_nested_all_attr(attrs: &[Attribute]) -> syn::Result<bool> {
    let mut nested_all = false;
    for attr in attrs {
        if !attr.path().is_ident("patch") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("nested_all") {
                nested_all = true;
                Ok(())
            } else {
                Err(meta.error("unsupported patch attribute"))
            }
        })?;
    }
    Ok(nested_all)
}

fn has_nested_attr(attrs: &[Attribute]) -> syn::Result<bool> {
    let mut nested = false;
    for attr in attrs {
        if !attr.path().is_ident("patch") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("nested") {
                nested = true;
                Ok(())
            } else {
                Err(meta.error("unsupported patch attribute"))
            }
        })?;
    }
    Ok(nested)
}

fn serde_field_attrs(attrs: &[Attribute]) -> Vec<Attribute> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("serde"))
        .filter_map(strip_serde_default)
        .collect()
}

fn strip_serde_default(attr: &Attribute) -> Option<Attribute> {
    let parsed = attr
        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .ok();

    match parsed {
        None => Some(attr.clone()),
        Some(args) => {
            let mut filtered = Punctuated::<Meta, Token![,]>::new();
            for meta in args {
                match &meta {
                    Meta::Path(path) if path.is_ident("default") => {}
                    Meta::NameValue(nv) if nv.path.is_ident("default") => {}
                    _ => filtered.push(meta),
                }
            }

            match filtered.is_empty() {
                true => None,
                false => Some(syn::parse_quote!(#[serde(#filtered)])),
            }
        }
    }
}

fn option_inner_type(ty: &Type) -> Option<&Type> {
    let segment = match ty {
        Type::Path(path) => Some(path),
        _ => None,
    }
    .filter(|path| path.qself.is_none())
    .and_then(|path| path.path.segments.last());

    let args = segment.and_then(|segment| match segment.ident == "Option" {
        true => match &segment.arguments {
            PathArguments::AngleBracketed(args) if args.args.len() == 1 => Some(args),
            _ => None,
        },
        false => None,
    });

    args.and_then(|args| match args.args.first() {
        Some(GenericArgument::Type(inner)) => Some(inner),
        _ => None,
    })
}

fn patch_type(ty: &Type) -> syn::Result<Type> {
    let type_path = match ty {
        Type::Path(path) => Ok(path),
        _ => Err(syn::Error::new_spanned(
            ty,
            "nested patch fields must be a path type",
        )),
    }?;

    let type_path = match type_path.qself.is_some() {
        true => Err(syn::Error::new_spanned(
            ty,
            "nested patch fields cannot use qualified self types",
        )),
        false => Ok(type_path),
    }?;

    let mut path = type_path.path.clone();
    let last = path
        .segments
        .last_mut()
        .ok_or_else(|| syn::Error::new_spanned(ty, "expected a path type"))?;

    last.ident = format_ident!("{}Patch", last.ident);

    Ok(Type::Path(TypePath { qself: None, path }))
}
