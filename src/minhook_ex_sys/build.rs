fn main() {
    fn get_hde_source() -> &'static str {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        match arch.as_str() {
            "x86" => "minhook/src/hde/hde32.c",
            "x86_64" => "minhook/src/hde/hde64.c",
            _ => panic!("unsupported target arch"),
        }
    }

    let includes = [
        "minhook/include/",
        "minhook/src/",
        "minhook/src/hde/",
    ];
    let sources = [
        "minhook/src/buffer.c",
        "minhook/src/hook.c",
        "minhook/src/trampoline.c",
        get_hde_source()
    ];

    cc::Build::new()
        .includes(includes)
        .files(sources)
        .compile("minhook");
}
