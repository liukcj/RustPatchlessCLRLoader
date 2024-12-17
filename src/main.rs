#![allow(non_snake_case, non_camel_case_types)]

mod loader;

fn main() -> Result<(), String> {
    loader::start_loader()
}
