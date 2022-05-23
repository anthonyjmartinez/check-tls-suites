// Copyright 2021-2022 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use anyhow::{anyhow, Result};
use clap::{crate_authors, crate_description, crate_version, Arg, Command};
use csv::Reader;
use serde::{Deserialize, Serialize};

fn args() -> Command<'static> {
    Command::new("Check TLS Suites")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::new("from_file")
             .short('f')
             .takes_value(true)
             .help("Path to the IANA TLS parameters CSV")
             .required_unless_present("from_web"))
        .arg(Arg::new("from_web")
             .short('f')
             .takes_value(false)
             .help("Download the IANA TLS parameters CSV from https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv")
             .required_unless_present("from_file"))
        .arg(Arg::new("int_list")
             .long("--int-list")
             .help("Provide a comma-separated list of cipher spec integer representations (from tshark for example)")
             .takes_value(true)
             .required_unless_present("hex_stream"))
        .arg(Arg::new("hex_stream")
             .long("--hex-stream")
             .takes_value(true)
             .help("Provide the hex stream of cipher specs (from Wireshark for example)")
             .required_unless_present("int_list"))
}

#[derive(Debug, Serialize, Deserialize)]
struct Suite {
    #[serde(rename = "Value")]
    val: String,
    #[serde(rename = "Description")]
    desc: String,
    #[serde(rename = "Recommended")]
    rec: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusMap {
    map: HashMap<Vec<u8>, Status>,
}

impl StatusMap {
    fn new() -> StatusMap {
        let map: HashMap<Vec<u8>, Status> = HashMap::new();
        StatusMap { map }
    }

    fn recommended(&self, key: Vec<u8>) {
        let hex_key = hex::encode_upper(&key);
        if let Some(status) = self.map.get(&key) {
            let status_name = &status.name;
            if status.rec {
                println!("Cipher suite '{status_name}, (0x{hex_key})' is recommended for use.");
            } else {
                println!("!Cipher suite '{status_name} (0x{hex_key})' is NOT recommended for use!");
            }
        } else {
            println!("Unknown cipher spec: {hex_key}")
        }
    }

    fn check_hex_stream(&self, hstream: &str) -> Result<()> {
        if hstream.len() % 2 == 0 {
            let vals = hex::decode(hstream)?;
            for suite_bytes in vals.chunks(2) {
                self.recommended(suite_bytes.to_vec());
            }
            Ok(())
        } else {
            Err(anyhow!("Invalid hex stream: {hstream}"))
        }
    }

    fn check_int_list(&self, int_list: &str) -> Result<()> {
        let int_vec: Vec<&str> = int_list.split(',').collect();
        for spec in int_vec {
            let mut val = vec![0];
            let spec_int: usize = spec.parse()?;

            let spec_hex: String = if spec_int < 16 {
                format!("0{spec_int:X}")
            } else {
                format!("{spec_int:X}")
            };

            let mut hex_val = hex::decode(&spec_hex)
                .with_context(|| format!("Failed on: {spec_hex}, int: {spec_int}"))?;

            if hex_val.len() < 2 {
                val.append(&mut hex_val);
            } else {
                val = hex_val;
            }

            self.recommended(val);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Status {
    name: String,
    rec: bool,
}

fn parse_iana_list<R: Read>(reader: R) -> Result<StatusMap> {
    let mut rdr = Reader::from_reader(reader);
    let iter = rdr.deserialize();

    let mut status_table = StatusMap::new();

    for rec in iter {
        let suite: Suite = rec?;

        if filter_reserved(&suite) || filter_unassigned(&suite) {
            continue;
        }

        let name = suite.val.trim_start_matches("0x").replace(",0x", "");

        let name = hex::decode(name)?;
        let status = Status {
            name: suite.desc.clone(),
            rec: suite.rec == "Y",
        };

        status_table.map.insert(name, status);
    }

    Ok(status_table)
}

fn filter_reserved(s: &Suite) -> bool {
    s.desc.contains("Reserved")
}

fn filter_unassigned(s: &Suite) -> bool {
    s.desc.contains("Unassigned")
}

fn tls_params_from_disk<P: AsRef<Path>>(path: P) -> Result<BufReader<File>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    Ok(reader)
}

fn tls_params_from_web() -> Result<String> {
    static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

    let client = reqwest::blocking::Client::builder()
        .user_agent(APP_USER_AGENT)
        .build()?;

    let tls_params = client
        .get("https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv")
        .send()?
        .text()?;

    Ok(tls_params)
}

fn main() -> Result<()> {
    let matches = args().get_matches();

    let suite_table: StatusMap = if matches.is_present("from_file") {
        let reader = tls_params_from_disk(matches.value_of("from_file").unwrap())?;
        parse_iana_list(reader)?
    } else {
        let reader = tls_params_from_web()?;
        parse_iana_list(reader.as_bytes())?
    };

    if matches.is_present("hex_stream") {
        let hex_stream = matches.value_of("hex_stream").unwrap();
        suite_table.check_hex_stream(hex_stream)?;
    } else {
        let int_list = matches.value_of("int_list").unwrap();
        suite_table.check_int_list(int_list)?;
    }

    Ok(())
}
