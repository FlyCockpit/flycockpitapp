use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::{Val, read};

const VERSION: &str = "jaq 3.1.0 (cockpit-bundled, jq-compatible)";
const HELP: &str = "\
Usage: cockpit jq [options] <filter> [file...]

Options:
  -r, --raw-output       write strings without JSON quotes
  -c, --compact-output   compact JSON output
  -s, --slurp            read all inputs into an array
  -n, --null-input       run the filter once with null input
  -e, --exit-status      set exit code from the last output value
  -j, --join-output      do not print a newline after each output
  -f, --from-file        read the filter from a file
      --arg NAME VALUE   bind a string variable
      --argjson NAME JSON bind a JSON variable
      --slurpfile NAME FILE bind an array of JSON values read from FILE
      --tab              indent with tabs
      --indent N         indent with N spaces
      --version          print version
      --help             print help
";

#[derive(Default)]
struct JqOptions {
    raw_output: bool,
    compact_output: bool,
    slurp: bool,
    null_input: bool,
    exit_status: bool,
    join_output: bool,
    from_file: bool,
    tab: bool,
    indent: Option<usize>,
    arg: Vec<(String, String)>,
    argjson: Vec<(String, String)>,
    slurpfile: Vec<(String, PathBuf)>,
    filter: Option<String>,
    files: Vec<PathBuf>,
}

pub async fn run(args: crate::cli::JqArgs) -> Result<()> {
    let code = run_from_args(args.args)?;
    if code == 0 {
        Ok(())
    } else {
        std::process::exit(i32::from(code));
    }
}

pub fn run_from_argv0() -> ExitCode {
    match run_from_args(std::env::args_os().skip(1).collect()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("cockpit jq: {error:#}");
            ExitCode::from(2)
        }
    }
}

pub fn run_from_args(args: Vec<OsString>) -> Result<u8> {
    let opts = parse_args(args)?;
    run_opts(opts)
}

fn parse_args(args: Vec<OsString>) -> Result<JqOptions> {
    let mut opts = JqOptions::default();
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(s) = arg.to_str() else {
            positional(&mut opts, arg)?;
            continue;
        };
        if s == "--" {
            for rest in iter {
                positional(&mut opts, rest)?;
            }
            break;
        }
        if let Some(flag) = s.strip_prefix("--") {
            match flag {
                "raw-output" => opts.raw_output = true,
                "compact-output" => opts.compact_output = true,
                "slurp" => opts.slurp = true,
                "null-input" => opts.null_input = true,
                "exit-status" => opts.exit_status = true,
                "join-output" => {
                    opts.join_output = true;
                    opts.raw_output = true;
                }
                "from-file" => opts.from_file = true,
                "tab" => opts.tab = true,
                "indent" => {
                    opts.indent = Some(
                        next_value(&mut iter, "--indent")?
                            .parse()
                            .with_context(|| {
                                "--indent expects a non-negative integer".to_string()
                            })?,
                    );
                }
                "arg" => {
                    let name = next_value(&mut iter, "--arg")?;
                    let value = next_value(&mut iter, "--arg")?;
                    opts.arg.push((name, value));
                }
                "argjson" => {
                    let name = next_value(&mut iter, "--argjson")?;
                    let value = next_value(&mut iter, "--argjson")?;
                    opts.argjson.push((name, value));
                }
                "slurpfile" => {
                    let name = next_value(&mut iter, "--slurpfile")?;
                    let path = next_value(&mut iter, "--slurpfile")?;
                    opts.slurpfile.push((name, PathBuf::from(path)));
                }
                "version" => {
                    println!("{VERSION}");
                    std::process::exit(0);
                }
                "help" => {
                    print!("{HELP}");
                    std::process::exit(0);
                }
                "ascii-output" | "stream" | "seq" | "jsonargs" | "unbuffered" | "stream-errors" => {
                    unsupported(format!("--{flag}"))?
                }
                _ => bail!("unknown jq flag `--{flag}`"),
            }
            continue;
        }
        if let Some(flags) = s.strip_prefix('-')
            && !flags.is_empty()
        {
            for flag in flags.chars() {
                match flag {
                    'r' => opts.raw_output = true,
                    'c' => opts.compact_output = true,
                    's' => opts.slurp = true,
                    'n' => opts.null_input = true,
                    'e' => opts.exit_status = true,
                    'j' => {
                        opts.join_output = true;
                        opts.raw_output = true;
                    }
                    'f' => opts.from_file = true,
                    'a' => unsupported("-a")?,
                    _ => bail!("unknown jq flag `-{flag}`"),
                }
            }
            continue;
        }
        positional(&mut opts, arg)?;
    }
    Ok(opts)
}

fn unsupported(flag: impl AsRef<str>) -> Result<()> {
    bail!(
        "unsupported jq flag `{}` in cockpit-bundled jq-compatible implementation",
        flag.as_ref()
    )
}

fn next_value<I>(iter: &mut std::iter::Peekable<I>, flag: &'static str) -> Result<String>
where
    I: Iterator<Item = OsString>,
{
    let value = iter
        .next()
        .with_context(|| format!("{flag} expects a value"))?;
    value
        .into_string()
        .map_err(|value| anyhow::anyhow!("{flag} value is not valid UTF-8: {value:?}"))
}

fn positional(opts: &mut JqOptions, arg: OsString) -> Result<()> {
    if opts.filter.is_none() {
        let value = arg
            .into_string()
            .map_err(|value| anyhow::anyhow!("filter is not valid UTF-8: {value:?}"))?;
        opts.filter = Some(value);
    } else {
        opts.files.push(PathBuf::from(arg));
    }
    Ok(())
}

fn run_opts(opts: JqOptions) -> Result<u8> {
    let filter_code = match (opts.filter.as_deref(), opts.from_file) {
        (Some(path), true) => std::fs::read_to_string(path)
            .with_context(|| format!("reading jq filter file `{path}`"))?,
        (Some(code), false) => code.to_string(),
        (None, _) => ".".to_string(),
    };

    let mut bindings = Vec::new();
    for (name, value) in &opts.arg {
        bindings.push((name.clone(), Val::utf8_str(value.clone())));
    }
    for (name, value) in &opts.argjson {
        let parsed = read::parse_single(value.as_bytes())
            .map_err(|e| anyhow::anyhow!("--argjson {name}: {e}"))?;
        bindings.push((name.clone(), parsed));
    }
    for (name, path) in &opts.slurpfile {
        let content =
            std::fs::read(path).with_context(|| format!("reading `{}`", path.display()))?;
        let vals = parse_values(&content)
            .with_context(|| format!("parsing `{}` for --slurpfile {name}", path.display()))?;
        bindings.push((name.clone(), vals.into_iter().collect()));
    }

    let names = bindings
        .iter()
        .map(|(name, _)| format!("${name}"))
        .collect::<Vec<_>>();
    let values = bindings
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();

    let filter = compile_filter(&filter_code, &names)?;
    let inputs = read_inputs(&opts)?;
    let mut outputs = Vec::new();
    for input in inputs {
        let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new(values.clone()));
        for output in filter.id.run((ctx, input)).map(unwrap_valr) {
            outputs.push(output.map_err(|e| anyhow::anyhow!("{e}"))?);
        }
    }

    write_outputs(&outputs, &opts)?;
    if opts.exit_status {
        return Ok(exit_status_for(outputs.last()));
    }
    Ok(0)
}

fn compile_filter(code: &str, vars: &[String]) -> Result<jaq_core::Filter<data::JustLut<Val>>> {
    let program = File { code, path: () };
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let modules = loader
        .load(&arena, program)
        .map_err(|reports| anyhow::anyhow!("failed to parse jq filter: {reports:?}"))?;
    let vars = vars.iter().map(String::as_str);
    Compiler::default()
        .with_funs(funs)
        .with_global_vars(vars)
        .compile(modules)
        .map_err(|reports| anyhow::anyhow!("failed to compile jq filter: {reports:?}"))
}

fn read_inputs(opts: &JqOptions) -> Result<Vec<Val>> {
    if opts.null_input {
        return Ok(vec![Val::Null]);
    }
    let mut inputs = Vec::new();
    if opts.files.is_empty() {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        inputs.extend(parse_values(&buf)?);
    } else {
        for file in &opts.files {
            let content =
                std::fs::read(file).with_context(|| format!("reading `{}`", file.display()))?;
            inputs.extend(
                parse_values(&content)
                    .with_context(|| format!("parsing JSON input from `{}`", file.display()))?,
            );
        }
    }
    if opts.slurp {
        Ok(vec![inputs.into_iter().collect()])
    } else {
        Ok(inputs)
    }
}

fn parse_values(bytes: &[u8]) -> Result<Vec<Val>> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    read::parse_many(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn write_outputs(outputs: &[Val], opts: &JqOptions) -> Result<()> {
    let mut out = std::io::stdout().lock();
    for value in outputs {
        if opts.raw_output {
            match value {
                Val::TStr(_) | Val::BStr(_) => {
                    let bytes = value
                        .try_as_utf8_bytes_owned()
                        .or_else(|_| value.try_as_bytes_owned())
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    out.write_all(&bytes)?;
                }
                _ => write!(out, "{value}")?,
            }
        } else if opts.compact_output {
            write!(out, "{value}")?;
        } else {
            let parsed: serde_json::Value = serde_json::from_str(&value.to_string())
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
            if opts.tab {
                write!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&parsed)?.replace("  ", "\t")
                )?;
            } else if let Some(indent) = opts.indent {
                let pretty = serde_json::to_string_pretty(&parsed)?;
                write!(out, "{}", pretty.replace("  ", &" ".repeat(indent)))?;
            } else {
                write!(out, "{}", serde_json::to_string_pretty(&parsed)?)?;
            }
        }
        if !opts.join_output {
            writeln!(out)?;
        }
    }
    Ok(())
}

fn exit_status_for(last: Option<&Val>) -> u8 {
    match last {
        Some(Val::Null | Val::Bool(false)) => 1,
        Some(_) => 0,
        None => 4,
    }
}
