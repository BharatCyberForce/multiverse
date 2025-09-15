use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use regex::Regex;
use ipnetwork::IpNetwork;
use serde_json::Value;


//Colors
const R: &str = "\x1b[31m";
const G: &str = "\x1b[32m";
const Y: &str = "\x1b[33m";
const C: &str = "\x1b[36m";
const N: &str = "\x1b[0m";

//add http
fn pwn(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    for l in r.lines() {
        let l = l?;
        let t = l.trim();
        if t.is_empty() { continue; }
        let out = if t.starts_with("http://") || t.starts_with("https://") {
            t.to_string()
        } else {
            format!("http://{}", t)
        };
        writeln!(w, "{}", out)?;
    }
    Ok(())
}

//Remove Duplicate Sites
fn uniq(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    let mut s = HashSet::new();
    for l in r.lines() {
        let l = l?;
        let t = l.trim();
        if t.is_empty() { continue; }
        if s.insert(t.to_string()) { writeln!(w, "{}", t)?; }
    }
    Ok(())
}

//Remove Extra Path
fn dom(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let rx = Regex::new(r"^https?://(?:www\\.)?(?P<domain>[^/]+)").unwrap();
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    for l in r.lines() {
        let l = l?;
        let t = l.trim();
        if t.is_empty() { continue; }
        if let Some(c) = rx.captures(t) {
            if let Some(d) = c.name("domain") { writeln!(w, "{}", d.as_str())?; continue; }
        }
        if let Some(p) = t.find('/') { writeln!(w, "{}", &t[..p])?; } else { writeln!(w, "{}", t)?; }
    }
    Ok(())
}

//wordpress user pass pattern change
fn creds(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let rx = Regex::new(r"^(?:https?://)?(?P<user>[^:@/]+):(?P<pass>[^@/]+)@(?P<host>[^/]+)").unwrap();
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    for l in r.lines() {
        let l = l?;
        let t = l.trim();
        if t.is_empty() { continue; }
        if let Some(c) = rx.captures(t) {
            if let (Some(u), Some(p), Some(h)) = (c.name("user"), c.name("pass"), c.name("host")) {
                writeln!(w, "User: {}, Pass: {}, Host: {}", u.as_str(), p.as_str(), h.as_str())?;
            }
        }
    }
    Ok(())
}


//Sites Filter
fn flt(input: &str, output: &str, ext: &str) -> Result<(), Box<dyn Error>> {
    let mut e = ext.to_string();
    if !e.starts_with('.') { e.insert(0, '.'); }
    let rx = Regex::new(r"^https?://(?:www\\.)?(?P<domain>[^/]+)").unwrap();
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    for l in r.lines() {
        let l = l?;
        let t = l.trim();
        if t.is_empty() { continue; }
        if let Some(c) = rx.captures(t) {
            if let Some(d) = c.name("domain") {
                if d.as_str().ends_with(&e) { writeln!(w, "{}", t)?; }
                continue;
            }
        }
        if t.ends_with(&e) { writeln!(w, "{}", t)?; }
    }
    Ok(())
}


//Remove http and https
fn strip(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    for l in r.lines() {
        let l = l?;
        let mut t = l.trim().to_string();
        if t.starts_with("http://") { t.replace_range(..7, ""); }
        else if t.starts_with("https://") { t.replace_range(..8, ""); }
        if let Some(p) = t.find('/') { t.truncate(p); }
        if !t.is_empty() { writeln!(w, "{}", t)?; }
    }
    Ok(())
}


//Reverse IP Lookup
fn revip(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let mut ips = Vec::new();
    if Path::new(input).exists() {
        let r = BufReader::new(File::open(input)?);
        for l in r.lines() { let ip = l?.trim().to_string(); if !ip.is_empty() { ips.push(ip); } }
    } else { let ip = input.trim().to_string(); if !ip.is_empty() { ips.push(ip); } }
    let mut w = BufWriter::new(File::create(output)?);
    for ip in ips {
        let url = format!("https://api.reverseip.my.id/?ip={}", ip);
        let resp = reqwest::blocking::get(&url)?;
        if resp.status().is_success() {
            let v: Value = resp.json()?;
            if let Some(doms) = v.get("domains").and_then(|d| d.as_array()) {
                writeln!(w, "IP {} doms:", ip)?;
                for d in doms { if let Some(s) = d.as_str() { writeln!(w, "  {}", s)?; } }
            } else if let Some(arr) = v.as_array() {
                writeln!(w, "IP {} doms:", ip)?;
                for d in arr { if let Some(s) = d.as_str() { writeln!(w, "  {}", s)?; } }
            } else { writeln!(w, "IP {}: {:?}", ip, v)?; }
        } else { writeln!(w, "Fail {}: {}", ip, resp.status())?; }
    }
    Ok(())
}


//asn to ip
fn bgp(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let mut asns = Vec::new();
    if Path::new(input).exists() {
        let r = BufReader::new(File::open(input)?);
        for l in r.lines() { let mut a = l?.trim().to_uppercase(); if a.is_empty() { continue; } if !a.starts_with("AS") { a = format!("AS{}", a); } asns.push(a); }
    } else { let mut a = input.trim().to_uppercase(); if !a.starts_with("AS") { a = format!("AS{}", a); } if !a.is_empty() { asns.push(a); } }
    let mut w = BufWriter::new(File::create(output)?);
    for a in asns {
        let url = format!("https://api.bgpview.io/asn/{}/prefixes", a);
        let resp = reqwest::blocking::get(&url)?;
        if resp.status().is_success() {
            let v: Value = resp.json()?;
            if let Some(pfx) = v.get("ipv4_prefixes").and_then(|d| d.as_array()) {
                writeln!(w, "{} IPv4:", a)?;
                for p in pfx { if let Some(pr) = p.get("prefix").and_then(|x| x.as_str()) { writeln!(w, "  {}", pr)?; } }
            } else { writeln!(w, "{}: none", a)?; }
        } else { writeln!(w, "Fail {}: {}", a, resp.status())?; }
    }
    Ok(())
}


//cidr to ip range
fn range(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let r = BufReader::new(File::open(input)?);
    let mut w = BufWriter::new(File::create(output)?);
    for l in r.lines() {
        let c = l?.trim().to_string(); if c.is_empty() { continue; }
        match c.parse::<IpNetwork>() {
            Ok(n) => match n {
                IpNetwork::V4(n4) => { let s = n4.network(); let e = n4.broadcast(); writeln!(w, "{}-{}", s, e)?; }
                IpNetwork::V6(n6) => { let s = n6.network(); let e = n6.broadcast(); writeln!(w, "{}-{}", s, e)?; }
            },
            Err(_) => writeln!(w, "Bad: {}", c)?,
        }
    }
    Ok(())
}

//input
fn ask(prompt: &str) -> String {
    print!("{}{}{}", C, prompt, N);
    io::stdout().flush().unwrap();
    let mut b = String::new();
    io::stdin().read_line(&mut b).expect("in");
    b.trim().to_string()
}

fn main() {
    let banner = format!("{}{}{}\n", G, r#"
                       888 888    d8b                                              
                       888 888    Y8P                                              
                       888 888                                                    
88888b.d88b.  888  888 888 888888 888 888  888  .d88b.  888d888 .d8888b   .d88b.  
888 "888 "88b 888  888 888 888    888 888  888 d8P  Y8b 888P"   88K      d8P  Y8b 
888  888  888 888  888 888 888    888 Y88  88P 88888888 888     "Y8888b. 88888888 
888  888  888 Y88b 888 888 Y88b.  888  Y8bd8P  Y8b.     888          X88 Y8b.     
888  888  888  "Y88888 888  "Y888 888   Y88P    "Y8888  888      88888P'  "Y8888  
                                                                                 
                                                        bY Indian Cyber Force                                                    
                                                                                "#, N);
    print!("{}", banner);
    loop {
        println!("1 Add Http");
        println!("2 Remove Duplicates");
        println!("3 Remove Extra Path");
        println!("4 Parse wp user:pass url");
        println!("5 Filter Domain");
        println!("6 Remove http/https");
        println!("7 RevIP Lookup");
        println!("8 ASN to IP");
        println!("9 CIDR to IP Range");
        println!("0 Exit");

        let c = ask("multiverse@root:~/$ "); if c == "0" { break; }
        match c.as_str() {
            "1" => { let i = ask("In: "); let o = ask("Out: "); if let Err(e) = pwn(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "2" => { let i = ask("In: "); let o = ask("Out: "); if let Err(e) = uniq(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "3" => { let i = ask("In: "); let o = ask("Out: "); if let Err(e) = dom(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "4" => { let i = ask("In: "); let o = ask("Out: "); if let Err(e) = creds(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "5" => { let i = ask("In: "); let ex = ask("Ext: "); let o = ask("Out: "); if let Err(e) = flt(&i, &o, &ex) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "6" => { let i = ask("In: "); let o = ask("Out: "); if let Err(e) = strip(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "7" => { let i = ask("IP/File: "); let o = ask("Out: "); if let Err(e) = revip(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "8" => { let i = ask("ASN/File: "); let o = ask("Out: "); if let Err(e) = bgp(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            "9" => { let i = ask("In: "); let o = ask("Out: "); if let Err(e) = range(&i, &o) { println!("{}Err:{} {}{}", R, N, e, N); } else { println!("{}Ok{}", G, N); } }
            _ => { println!("{}No{}", Y, N); }
        }
        println!();
    }
    println!("{}Bye{}", C, N);
}
