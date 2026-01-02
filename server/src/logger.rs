const RESET: &str = "\x1b[0m";
#[allow(dead_code)]
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
#[allow(dead_code)]
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";
const DARK_BLUE: &str = "\x1b[36m";

pub fn log(message: &str) {
    println!("{}[INFO]{} {}", DARK_BLUE, RESET, message);
}

#[allow(dead_code)]
pub fn error(message: &str) {
    println!("{}[ERROR]{} {}", RED, RESET, message);
}

pub fn warn(message: &str) {
    println!("{}[WARN]{} {}", YELLOW, RESET, message);
}

#[allow(dead_code)]
pub fn debug(message: &str) {
    println!("{}[DEBUG]{} {}", BLUE, RESET, message);
}

pub fn success(message: &str) {
    println!("{}[SUCCESS]{} {}", GREEN, RESET, message);
}
