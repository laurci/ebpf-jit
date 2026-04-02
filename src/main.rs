mod compiler;

use std::fs;

use aya::programs::{tc, SchedClassifier, TcAttachType};
use clap::Parser;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "tap-test1")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    use std::net::Ipv4Addr;

    let allow_subnets_fast_path = vec![
        (Ipv4Addr::new(10, 60, 0, 0), 16u8), // allow 10.60.0.0/16
    ];
    let allowed_ips = vec![Ipv4Addr::new(10, 69, 42, 2)];

    let start_time = std::time::Instant::now();
    let elf_bytes = compiler::compile_filter(&allow_subnets_fast_path, &allowed_ips)?;
    let duration = start_time.elapsed();

    fs::write("target/filter.o", &elf_bytes)?;

    println!(
        "compiled target/filter.o ({} bytes) in {:?}",
        elf_bytes.len(),
        duration
    );

    println!("allowed subnets fast path: {:?}", allow_subnets_fast_path);
    println!("allowed IPs: {:?}", allowed_ips);

    // Disassemble to see what LLVM generated
    if let Ok(output) = std::process::Command::new("llvm-objdump")
        .args(["-d", "target/filter.o"])
        .output()
    {
        eprintln!(
            "Generated EBPF bytecode:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    } else {
        eprintln!("failed to disassemble target/filter.o, is llvm-objdump installed?");
    }

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(&elf_bytes)?;

    let Opt { iface } = opt;

    // cleanup. might need to implement this in tc properly.
    let _ = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", &iface, "clsact"])
        .output();

    tc::qdisc_add_clsact(&iface)?;

    let prog: &mut SchedClassifier = ebpf.program_mut("vm_filter").unwrap().try_into()?;
    prog.load()?;
    let attach_id = prog.attach(&iface, TcAttachType::Egress)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    prog.detach(attach_id)?;

    Ok(())
}
