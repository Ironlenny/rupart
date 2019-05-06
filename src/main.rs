use exitfailure::ExitFailure;
use structopt::StructOpt;
// use failure::ResultExt;
use std::path::PathBuf;

// Command-line struct
#[derive(Debug, StructOpt)]
#[structopt(about = "The Rust Parity archival program", author = "Jacob Riddle")]
struct Args {
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() -> Result<(), ExitFailure> {
    let args = Args::from_args();

    Ok(())
}
