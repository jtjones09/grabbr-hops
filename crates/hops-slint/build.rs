fn main() {
    // Debug builds, which the tests are, carry the element info the testing
    // backend's search needs, so a test can find a widget and drag it as a
    // person would. A release build is compiled without it, so those tests
    // (the canvas drags) run in the debug profile only, as CI runs them.
    let debug = std::env::var("PROFILE").as_deref() == Ok("debug");
    let config = slint_build::CompilerConfiguration::new().with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile app.slint");
}
