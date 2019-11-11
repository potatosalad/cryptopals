// build.rs

fn main() {
    cc::Build::new()
        .file("src/set03/challenge21/mersenne_twister_engine.cc")
        .cpp(true)
        .compile("mersenne_twister_engine");
    println!("cargo:rerun-if-changed=src/set03/challenge21/mersenne_twister_engine.cc");
}
