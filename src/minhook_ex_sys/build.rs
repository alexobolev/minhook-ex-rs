fn main() {
    use std::env;
    let hde_source_file: &'static str = {
        let arch = env::var("CARGO_CFG_TARGET_ARCH");
        match arch.unwrap().as_str() {
            "x86" => "minhook/src/hde/hde32.c",
            "x86_64" => "minhook/src/hde/hde64.c",
            _ => panic!("unsupported target arch"),
        }
    };

    let includes = [
        "minhook/include/",
        "minhook/src/",
        "minhook/src/hde/",
    ];
    let sources = [
        "minhook/src/buffer.c",
        "minhook/src/hook.c",
        "minhook/src/trampoline.c",
        hde_source_file,
    ];

    cc::Build::new()
        .includes(includes)
        .files(sources)
        .compile("minhook");
}
