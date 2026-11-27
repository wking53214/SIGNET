//! signet-verify: check a registry, a signature or a checkpoint without signet. Exit 0: it checks. 1: it does not.
//! 2: the command was wrong.
//!
//!     signet-verify registry   ROOT_HEX REGISTRY_FILE [MIN_VERSION]
//!     signet-verify signature  ROOT_HEX REGISTRY_FILE PURPOSE DATA_FILE SIGNATURE_HEX
//!     signet-verify checkpoint ROOT_HEX REGISTRY_FILE CHECKPOINT_FILE

use std::process::ExitCode;

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn run(args: &[String]) -> Result<bool, String> {
    let reg = |min: i64| -> Result<signet_verify::Registry, String> {
        signet_verify::load_registry(&read(&args[2])?, &args[1], min)
    };
    match (args.first().map(String::as_str), args.len()) {
        (Some("registry"), 3 | 4) => {
            let min = args
                .get(3)
                .map_or(Ok(1), |m| m.parse::<i64>().map_err(|e| e.to_string()))?;
            match reg(min) {
                Ok(r) => {
                    println!("signet-verify: registry version {} checks", r.version);
                    Ok(true)
                }
                Err(e) => {
                    eprintln!("signet-verify: {e}");
                    Ok(false)
                }
            }
        }
        (Some("signature"), 6) => {
            let r = reg(1)?;
            let sig: Vec<u8> = (0..args[5].len() / 2)
                .map(|i| u8::from_str_radix(args[5].get(2 * i..2 * i + 2).unwrap_or("zz"), 16))
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            let ok = r.verify(&args[3], &read(&args[4])?, &sig);
            println!(
                "signet-verify: signature {}",
                if ok { "checks" } else { "does not check" }
            );
            Ok(ok)
        }
        (Some("checkpoint"), 4) => match reg(1)?.read_checkpoint(&read(&args[3])?) {
            Ok(c) => {
                println!(
                    "signet-verify: checkpoint of {} entries, head {}, checks",
                    c.length, c.head
                );
                Ok(true)
            }
            Err(e) => {
                eprintln!("signet-verify: {e}");
                Ok(false)
            }
        },
        _ => Err(
            "usage: signet-verify registry|signature|checkpoint ... (see the source header)".into(),
        ),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("signet-verify: {e}");
            ExitCode::from(2)
        }
    }
}
