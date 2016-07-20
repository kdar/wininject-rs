extern crate wininject;

fn main() {
  // println!("{:?}", getProcessBits(5332));
  // println!("{:?}", getPEBits("hook64.dll"));
  match wininject::inject("hook64.dll", 10368) {
    Err(e) => println!("{}", e),
    Ok(()) => (),
  }
}
