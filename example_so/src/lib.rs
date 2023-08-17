use ctor::*;

#[ctor]
fn constructor() {
    println!("Injected!");
}
