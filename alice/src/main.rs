use num_primes::Generator;
use std::io;
use rug::Integer;
use std::net::TcpStream;
use std::io::{prelude::*,BufReader,Write};
use ring::rand::{SystemRandom, SecureRandom};

fn generate_keypair() -> ((Integer, Integer), Integer) {
    let rand = SystemRandom::new();
    println!("Generating keypair...");
    let p = Integer::from_str_radix(&Generator::safe_prime(256).to_string(), 10).unwrap();
    let q = Integer::from_str_radix(&Generator::safe_prime(256).to_string(), 10).unwrap();
    let n = p.clone() * q.clone();
    let lambda = Integer::lcm(p - Integer::from(1), &(q - Integer::from(1)));
    let mut e;
    loop {
        e = random_integer(&rand, lambda.clone());
        if e.clone().gcd(&lambda) == 1 {
            break;
        };
    };
    let d = Integer::invert(e.clone(), &lambda).unwrap();
    ((n, e), d)
}

fn random_integer(rng: &SystemRandom, range: Integer) -> Integer {
    loop {
        let mut bytes = vec![0; ((range.significant_bits() + 7) / 8) as usize];
        rng.fill(&mut bytes).unwrap();
        let num = Integer::from_digits(&bytes, rug::integer::Order::Lsf);
        if num < range {
            return num;
        }
    }
}

fn combine_values(v: &Integer, randoms: &Vec<Integer>, d: &Integer, n: &Integer, messages: &[Integer]) -> Vec<String> {
    let mut ciphertexts: Vec<String> = Vec::new();
    for i in 0..randoms.len() {
        let mi = messages[i].clone() + Integer::secure_pow_mod(v.clone() - randoms[i].clone(), d, n);
        ciphertexts.push(base64::encode(mi.to_string()));
    }
    ciphertexts
}

fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:6969").expect("Failed to connect");
    let rand = SystemRandom::new();
    let ((n, e), d) = generate_keypair();
    let mut alice_sends_bob: Vec<String> = Vec::new();
    let mut input = String::new();
    let mut messages: Vec<Integer> = Vec::new();
    let mut randoms: Vec<Integer> = Vec::new();
    print!("\nHow many messages? ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let number = input.trim().parse().unwrap();
    println!();
    for i in 0..number {
        let mut input = String::new();
        print!("Enter message {i}: ");
        io::stdout().flush().unwrap();
        io::stdin()
            .read_line(&mut input)
            .unwrap();
        let input = input.trim();
        messages.push(Integer::from_str_radix(&hex::encode(input), 16).unwrap());
    }
    alice_sends_bob.push(base64::encode(n.to_string()));
    alice_sends_bob.push(base64::encode(e.to_string()));
    for _ in 0..number {
        let xi = random_integer(&rand, n.clone());
        alice_sends_bob.push(base64::encode(xi.to_string()));
        randoms.push(xi);
    }
    let joined_string = alice_sends_bob.join(" ");
    println!("\nSending public key and random messages to Bob...");
    stream.write_all(joined_string.as_bytes()).expect("failed to write");
    stream.flush().unwrap();
    let stream = TcpStream::connect("127.0.0.1:6969").expect("Failed to connect");
    let mut reader = BufReader::new(&stream);
    let mut buffer: Vec<u8> = Vec::new();
    reader.read_until(b'\n',&mut buffer).unwrap();
    let string = String::from_utf8(base64::decode(buffer).unwrap()).unwrap();
    let v = Integer::from_str_radix(string.as_str(), 10).unwrap();
    let ciphertexts = combine_values(&v, &randoms, &d, &n, &messages);
    let mut stream = TcpStream::connect("127.0.0.1:6969").expect("Failed to connect");
    let joined_string = ciphertexts.join(" ");
    println!("\nSending ciphertexts to Bob...");
    stream.write_all(joined_string.as_bytes()).expect("failed to write");
    println!("\nConnection terminated.");
}
