use std::io::Write;

use ezkl_lib::eth::fix_verifier_sol;

fn main() {
    let cwd = std::env::current_dir().unwrap();
    let sol_code = fix_verifier_sol(cwd.join("verifier.yul")).unwrap();
    let mut f = std::fs::File::create("verifier.sol").unwrap();
    write!(&mut f, "{}", sol_code).unwrap();
}
