use num_primes::Generator;
use std::io;
use std::io::Write;
use rug::{Integer, rand};

fn generate_keypair() -> ((Integer, Integer), Integer) {
    println!("Generating keypair...");
    let p = Integer::from_str_radix(&Generator::safe_prime(256).to_string(), 10).unwrap();
    let q = Integer::from_str_radix(&Generator::safe_prime(256).to_string(), 10).unwrap();
    let n = p.clone() * q.clone();
    let lambda = Integer::lcm(p - Integer::from(1), &(q - Integer::from(1)));
    let mut e;
    let mut rand = rand::RandState::new();
    loop {
        e = lambda.clone().random_below(&mut rand);
        if e.clone().gcd(&lambda) == 1 {
            break;
        };
    };
    let d = Integer::invert(e.clone(), &lambda).unwrap();
    ((n, e), d)
}

fn combine_values(v: &Integer, randoms: &Vec<Integer>, d: &Integer, n: &Integer, messages: &[Integer]) -> Vec<Integer> {
    let mut ciphertexts: Vec<Integer> = Vec::new();
    for i in 0..randoms.len() {
        ciphertexts.push(messages[i].clone() + Integer::secure_pow_mod(v.clone() - randoms[i].clone(), d, n));
    }
    ciphertexts
}

fn main() {
    let ((n, e), d) = generate_keypair();
    println!("\nPublic key: (n, e)");
    println!("n: {}", base64::encode(n.to_string()));
    println!("e: {}", base64::encode(e.to_string()));
    println!("\nSecret key: {}", base64::encode(d.to_string()));
    let mut input = String::new();
    let mut messages: Vec<Integer> = Vec::new();
    let mut randoms: Vec<Integer> = Vec::new();
    print!("\nHow many messages? ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let number = input.trim().parse().unwrap();
    for i in 0..number {
        let mut input = String::new();
        print!("\nEnter m{i}: ");
        io::stdout().flush().unwrap();
        io::stdin()
            .read_line(&mut input)
            .unwrap();
        let input = input.trim();
        messages.push(Integer::from_str_radix(&hex::encode(input), 16).unwrap());
    }
    let mut rand = rand::RandState::new();
    for i in 0..number {
        let xi = n.clone().random_below(&mut rand);
        print!("\nx{i}: {}", base64::encode(xi.to_string()));
        randoms.push(xi);
    }
    print!("\n\nEnter v: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let v = Integer::from_str_radix(input, 10).unwrap();
    let ciphertexts = combine_values(&v, &randoms, &d, &n, &messages);
    println!();
    for (index, element) in ciphertexts.iter().enumerate() {
        println!("ciphertext {index}: {}", base64::encode(element.clone().to_string()));
        io::stdout().flush().unwrap();
    }
}
