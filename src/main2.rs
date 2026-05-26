use libbpf_rs::TcHookBuilder;
fn test() {
    let mut builder = TcHookBuilder::new();
    builder.fd(1).ifindex(1).replace(true).handle(1).priority(1);
}
