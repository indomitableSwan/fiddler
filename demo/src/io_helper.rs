//! Utility function to help obtain a command from user via CLI.

use anyhow::Result;
use std::{io, str::FromStr};
// TODO: this loop and match statment plus a return line is probably not
// idiomatic
//
/// Processes command line input and converts to type `T` as specified
/// by caller. If successful, returns conversion. If not, prints clarifying
/// instructions so that the person can try again.
pub fn process_input<T, F>(instr: F) -> Result<T>
where
    T: FromStr,
    F: Fn(),
{
    loop {
        // Print the instructions
        instr();

        let mut input = String::new();

        io::stdin().read_line(&mut input)?;

        let result: T = match input.trim().parse::<T>() {
            Ok(txt) => txt,
            Err(_e) => {
                //println!("Error. {}", e);
                continue;
            }
        };

        return Ok(result);
    }
}
