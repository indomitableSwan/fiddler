//! Utility function to help obtain a command from user via CLI.

use anyhow::Result;
use std::{io, os::unix::process, str::FromStr, sync::Condvar};

use crate::menu::ConsentMenu;
// TODO: this loop and match statment plus a return line is probably not
// idiomatic
//
/// Processes command line input and converts to type `T` as specified
/// by caller. If successful, returns conversion. If not, prints clarifying
/// instructions so that the person can try again.
pub fn process_input<T, F, R>(instr: F, mut reader: R) -> Result<T>
where
    T: FromStr,
    F: Fn(),
    R: io::BufRead
{
    loop {
        // Print the instructions
        instr();

        let mut input = String::new();

        reader.read_line(&mut input)?;

        let result: T = match input.trim().parse::<T>() {
            Ok(txt) => txt,
            Err(_) => {
                continue;
            }
        };

        return Ok(result);
    }
}

mod test {
    use super::*;

#[test]
fn assent(){
    let input: &[u8] = b"y";
    let command: ConsentMenu = process_input(||{}, input).unwrap();
    assert_eq!(command, ConsentMenu::YesKE)}
}

#[test]
fn dissent(){
    let input: &[u8] = b"n";
    let command: ConsentMenu = process_input(||{}, input).unwrap();
    assert_eq!(command, ConsentMenu::NoKE)
}

#[test]
#[should_panic]
fn consent_error(){
    let input: &[u8] = b"N";
    let error: anyhow::Error = process_input::<ConsentMenu, _, &[u8]>(||{}, input).unwrap_err();
   
    //assert_eq!(error.downcast_ref::, ConsentMenu::NoKE)
}