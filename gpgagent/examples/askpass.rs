extern crate gpgagent;

fn main() {
    let mut agent = gpgagent::GpgAgent::from_standard_paths()
        .unwrap();
    agent.setopt_ttyname().unwrap();
    agent.clear_passphrase("gpgagent:rust:example").unwrap();
    let password = agent.get_passphrase("gpgagent:rust:example", "opening vault", "prompt", "the vault")
        .unwrap();
    println!("password: {}", String::from_utf8(password).unwrap());
}
