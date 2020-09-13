//! The argument gate: reject any flag a verb does not declare (#67).
//!
//! Both binaries parse args by hand (dependency-light by design — no clap), and
//! both used to scan for the flags they knew and ignore the rest. So
//! `loot log --path README.md` printed the whole **unfiltered** log, which reads
//! as "the filter ran and matched everything" (#67, pilot finding 11). Silently
//! accepting a flag we don't implement teaches users a feature exists. A flag we
//! don't understand must fail loudly.
//!
//! The rule is one implementation with two callers: `loot`'s dispatch table and
//! `loot-first`'s. On `loot-first` the same bug is sharper than a wrong printout
//! — an ignored `--dryrun` typo lands the PR for real.

/// The flags one verb understands. `valued` flags consume the argument after
/// them (`-m <message>`); `bare` flags stand alone (`--json`). Anything else
/// spelled like a flag is rejected before the verb runs.
///
/// Declared per verb, not per subcommand: `loot lane`'s spec is the union over
/// `new`/`gc`/…, which is what it takes to catch a flag that exists nowhere in
/// the CLI — the #67 class — without a second dispatch table to keep in step.
pub struct FlagSpec {
    /// The binary the verb belongs to, for the error text (`loot`, `loot-first`).
    pub bin: &'static str,
    pub name: &'static str,
    pub valued: &'static [&'static str],
    pub bare: &'static [&'static str],
}

/// What the gate decided for an argument list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagCheck {
    /// Every flag present is one this verb declares — run it.
    Proceed,
    /// `-h`/`--help` rode the verb: print usage instead of running it.
    Help,
}

impl FlagSpec {
    /// Check `args` against this verb's declared flags.
    ///
    /// A `valued` flag's value is skipped, so a value that happens to look like
    /// a flag (`describe -m "--wip: …"`) is never checked as one. `-h`/`--help`
    /// is accepted on every verb and short-circuits to usage — otherwise it
    /// would be the one flag still silently ignored, and on `loot new` a bare
    /// `--help` would *finalize (sign) the working change* instead of
    /// explaining it.
    pub fn check(&self, args: &[String]) -> Result<FlagCheck, String> {
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if a == "-h" || a == "--help" {
                return Ok(FlagCheck::Help);
            }
            if self.valued.contains(&a) {
                i += 2; // the flag and the value it consumes
            } else if self.bare.contains(&a) {
                i += 1;
            } else if is_flag(a) {
                return Err(self.unknown(a));
            } else {
                i += 1; // a positional
            }
        }
        Ok(FlagCheck::Proceed)
    }

    /// The refusal — it names the offending flag and lists what this verb does
    /// accept, so the fix is visible without a trip to the usage text.
    fn unknown(&self, flag: &str) -> String {
        let mut known: Vec<&str> = self.valued.iter().chain(self.bare).copied().collect();
        known.sort_unstable();
        let accepted = if known.is_empty() {
            format!("`{} {}` takes no flags", self.bin, self.name)
        } else {
            format!("`{} {}` accepts: {}", self.bin, self.name, known.join(", "))
        };
        // `--help` prints the whole usage, not this verb's slice of it, so the
        // hint says `loot --help` — pointing at a per-verb usage that doesn't
        // exist would be this very bug in miniature.
        format!("unknown flag '{flag}' — {accepted}\n\nrun `{} --help` for usage", self.bin)
    }
}

/// Whether an argument is spelled like a flag. A bare `-` is not (it is the
/// conventional stdin/stdout stand-in, and no verb reads it as a flag).
fn is_flag(arg: &str) -> bool {
    arg.starts_with('-') && arg != "-"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // Synthetic specs, deliberately not copies of shipped verbs: this module
    // owns the *rule*, and each binary's table owns which flags its verbs take
    // (asserted against the real table there). A lookalike fixture here would
    // drift from the table it imitates while still passing.
    const NOFLAGS: FlagSpec = FlagSpec { bin: "toy", name: "noflags", valued: &[], bare: &[] };
    const BOTH: FlagSpec =
        FlagSpec { bin: "toy", name: "both", valued: &["-m", "--out"], bare: &["--loud", "--dry"] };

    /// The shape of the finding (pilot finding 11, #67): the verb takes no
    /// filter, so a flag asking for one must fail rather than run unfiltered.
    #[test]
    fn unknown_flag_is_rejected_not_ignored() {
        let err = NOFLAGS.check(&args(&["--path", "README.md"])).unwrap_err();
        assert!(err.contains("--path"), "the error names the offending flag: {err}");
        assert!(err.contains("takes no flags"), "this verb has none to offer: {err}");
    }

    /// The refusal lists what the verb *does* accept, so the fix is visible
    /// without a trip to the usage text.
    #[test]
    fn the_refusal_lists_the_flags_the_verb_accepts() {
        let err = BOTH.check(&args(&["--nope"])).unwrap_err();
        assert!(err.contains("--nope"), "the error names the offending flag: {err}");
        assert!(err.contains("`toy both` accepts: --dry, --loud, --out, -m"), "{err}");
        assert!(err.contains("run `toy --help` for usage"), "the hint points at real usage: {err}");
    }

    /// Declared flags pass — bare and valued, on either side of the
    /// positionals, in any order.
    #[test]
    fn declared_flags_pass_the_gate() {
        assert_eq!(BOTH.check(&args(&["--loud"])), Ok(FlagCheck::Proceed));
        assert_eq!(
            BOTH.check(&args(&["--out", "f", "positional", "--dry", "-m", "msg"])),
            Ok(FlagCheck::Proceed)
        );
        assert_eq!(NOFLAGS.check(&args(&[])), Ok(FlagCheck::Proceed));
    }

    /// A valued flag's value is never itself checked as a flag — a message may
    /// legitimately start with a dash.
    #[test]
    fn a_valued_flags_value_is_not_checked_as_a_flag() {
        assert_eq!(BOTH.check(&args(&["-m", "--wip: drop the old flag"])), Ok(FlagCheck::Proceed));
        assert_eq!(BOTH.check(&args(&["--out", "--loud"])), Ok(FlagCheck::Proceed));
    }

    /// Positionals ride through untouched, including a bare `-`.
    #[test]
    fn positionals_are_not_flags() {
        assert_eq!(NOFLAGS.check(&args(&["a3f9", "-"])), Ok(FlagCheck::Proceed));
    }

    /// `-h`/`--help` is accepted everywhere and short-circuits to usage. It is
    /// the one flag that was *dangerous* to ignore: `loot new --help` used to
    /// finalize (sign) the working change instead of printing help.
    #[test]
    fn help_rides_every_verb_and_never_runs_it() {
        assert_eq!(NOFLAGS.check(&args(&["-h"])), Ok(FlagCheck::Help));
        assert_eq!(BOTH.check(&args(&["--help"])), Ok(FlagCheck::Help));
        // Help wins over a bad flag beside it — the user is already asking how.
        assert_eq!(NOFLAGS.check(&args(&["--help", "--path", "x"])), Ok(FlagCheck::Help));
        // But a valued flag's value still isn't a flag: this `--help` is a message.
        assert_eq!(BOTH.check(&args(&["-m", "--help"])), Ok(FlagCheck::Proceed));
    }
}
