mod access;
mod availability;
mod data;
mod injection;
mod rust_specific;

use crate::model::CategorySpec;

pub fn specs() -> Vec<CategorySpec> {
    let mut output = Vec::new();
    output.extend(injection::specs());
    output.extend(data::specs());
    output.extend(access::specs());
    output.extend(availability::specs());
    output.extend(rust_specific::specs());
    output.sort_by_key(|spec| spec.category);
    output
}
