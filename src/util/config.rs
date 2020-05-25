use super::{paths, strings, time};
use std::borrow::{Borrow, Cow};
use std::collections::{hash_map, HashMap};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::num::{ParseFloatError, ParseIntError};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone)]
pub struct Config {
    data: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Error)]
pub enum ConfigDefaultError {
    #[error("Failed to determine GNUnet installation data directory")]
    NoDataDir,
    #[error("Failed to read Gnunet installation data directory. Reason: {source}")]
    ReadDataDir {
        #[from]
        source: io::Error,
    },
    #[error("Failed to load config file. Reason: {source}")]
    LoadFile {
        #[from]
        source: ConfigLoadRawError,
    },
}

#[derive(Debug, Error)]
pub enum ConfigLoadRawError {
    #[error("Failed to open file. Reason: {source}")]
    FileOpen {
        #[from]
        source: io::Error,
    },
    #[error("Failed to deserialize config. Reason: {source}")]
    Deserialize {
        #[from]
        source: ConfigDeserializeError,
    },
}

#[derive(Debug, Error)]
pub enum ConfigDeserializeError {
    #[error("I/O error reading from reader. Specifically: {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Failed to load inline configuration file. line {line_number}: Failed to load \"{filename}\" ({source})")]
    LoadInline {
        source: Box<ConfigLoadRawError>,
        line_number: usize,
        filename: String,
    },
    #[error("@INLINE@ directive in config but allow_inline is disabled. line {line_number}: Will not load file \"{filename}\"")]
    InlineDisabled {
        line_number: usize,
        filename: String,
    },
    #[error("Syntax error in configuration. line {line_number}: Failed to parse \"{line}\"")]
    Syntax { line_number: usize, line: String },
}

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("Failed to load system default configuration. Reason: {source}")]
    LoadDefault {
        #[from]
        source: ConfigDefaultError,
    },
    #[error("Failed to load the config file. Reason: {source}")]
    LoadFile {
        #[from]
        source: ConfigLoadRawError,
    },
}

#[derive(Debug, Error)]
pub enum ConfigGetIntError {
    #[error("The config does not contain a section with that name")]
    NoSection,
    #[error("The config section does contain that key")]
    NoKey,
    #[error("The value is not a valid u64. Details: {source}")]
    Parse {
        #[from]
        source: ParseIntError,
    },
}
#[derive(Debug, Error)]
pub enum ConfigGetFloatError {
    #[error("The config does not contain a section with that name")]
    NoSection,
    #[error("The config section does contain that key")]
    NoKey,
    #[error("The value is not a valid f32. Details: {source}")]
    Parse {
        #[from]
        source: ParseFloatError,
    },
}
#[derive(Debug, Error)]
pub enum ConfigGetRelativeTimeError {
    #[error("The config does not contain a section with that name")]
    NoSection,
    #[error("The config section does contain that key")]
    NoKey,
    #[error("The value is not a valid relative time. Reason: {source}")]
    Parse {
        #[from]
        source: strings::ParseQuantityWithUnitsError,
    },
}

#[derive(Debug, Error)]
pub enum ConfigGetFilenameError {
    #[error("The config does not contain a section with that name")]
    NoSection,
    #[error("The config section does contain that key")]
    NoKey,
    #[error("Failed to '$'-expand the config entry. Reason: {source}")]
    ExpandDollar {
        #[from]
        source: ConfigExpandDollarError,
    },
}

#[derive(Debug, Error)]
pub enum ConfigExpandDollarError {
    #[error("Tried to expand to an environment variable containing invalid unicode. variable: '{var_name}'")]
    NonUnicodeEnvVar { var_name: String },
    #[error("Syntax error in '$'-expansion. Error at byte position {pos}")]
    Syntax { pos: usize },
    #[error("Failed to expand variable. Variable not found in PATHS section or process environment: '{var_name}'")]
    UnknownVariable { var_name: String },
    #[error("'$'-expansion includes an unclosed '{{'")]
    UnclosedBraces,
}

impl Config {
    pub fn empty() -> Config {
        Config {
            data: HashMap::new(),
        }
    }

    pub fn load_raw<P: AsRef<Path>>(path: P) -> Result<Config, ConfigLoadRawError> {
        let f = File::open(path)?;
        Ok(Config::deserialize(f, true)?)
    }

    pub fn deserialize<R: Read>(
        read: R,
        allow_inline: bool,
    ) -> Result<Config, ConfigDeserializeError> {
        use self::ConfigDeserializeError::*;
        use regex::Regex;

        // TODO consider using regex! from regex_macro which should compile quicker
        let re_section = Regex::new(r"^\[(.+)\]$").unwrap();
        let re_key_value = Regex::new(r"^(.+)=(.*)$").unwrap();
        let re_inline = Regex::new(r"^(?i)@inline@ (.+)$").unwrap();

        let mut cfg = Config::empty();
        let mut section = String::new();
        let br = BufReader::new(read);
        for (i, res_line) in br.lines().enumerate() {
            let line_num = i + 1;
            let line_buf = res_line?;

            {
                let line = line_buf.trim();

                // ignore empty lines
                if line.is_empty() {
                    continue;
                }

                // ignore comments
                if line.starts_with('#') || line.starts_with('%') {
                    continue;
                }

                if let Some(caps) = re_inline.captures(line) {
                    let filename = caps.at(1).unwrap().trim(); // panic is logically impossible
                    if allow_inline {
                        let cfg_raw = match Config::load_raw(filename) {
                            Ok(cfg_raw) => cfg_raw,
                            Err(e) => {
                                return Err(LoadInline {
                                    source: Box::new(e),
                                    line_number: line_num,
                                    filename: filename.to_string(),
                                })
                            }
                        };
                        cfg.merge(cfg_raw);
                    } else {
                        return Err(InlineDisabled {
                            line_number: line_num,
                            filename: filename.to_string(),
                        });
                    }
                    continue;
                }

                if let Some(caps) = re_section.captures(line) {
                    section = caps.at(1).unwrap().to_string(); // panic is logically impossible
                    continue;
                }

                if let Some(caps) = re_key_value.captures(line) {
                    let key = caps.at(1).unwrap().trim();
                    let value = caps.at(2).unwrap().trim();

                    /*
                     * TODO: Make this less yukk. There's a whole bunch of unnecessary allocation
                     * and copying happening here.
                     */
                    match cfg.data.entry(section.clone()) {
                        hash_map::Entry::Occupied(mut soe) => {
                            match soe.get_mut().entry(key.to_string()) {
                                hash_map::Entry::Occupied(mut koe) => {
                                    koe.insert(value.to_string());
                                }
                                hash_map::Entry::Vacant(kve) => {
                                    kve.insert(value.to_string());
                                }
                            }
                        }
                        hash_map::Entry::Vacant(sve) => {
                            let map = sve.insert(HashMap::new());
                            map.insert(key.to_string(), value.to_string());
                        }
                    }
                    continue;
                };
            };

            return Err(Syntax {
                line_number: line_num,
                line: line_buf,
            });
        }
        Ok(cfg)
    }

    pub fn merge(&mut self, mut other: Config) {
        for (k, mut v) in other.data.drain() {
            match self.data.entry(k) {
                hash_map::Entry::Occupied(oe) => {
                    let map = oe.into_mut();
                    for (k, v) in v.drain() {
                        map.insert(k, v);
                    }
                }
                hash_map::Entry::Vacant(ve) => {
                    ve.insert(v);
                }
            }
        }
    }

    pub fn default() -> Result<Config, ConfigDefaultError> {
        use self::ConfigDefaultError::*;

        let mut data_dir = match paths::data_dir() {
            Some(dd) => dd,
            None => return Err(NoDataDir),
        };

        data_dir.push("config.d");
        let mut cfg = Config::empty();
        let rd = match std::fs::read_dir(data_dir) {
            Ok(dirent) => dirent,
            Err(e) => return Err(ReadDataDir { source: e }),
        };

        for res_dirent in rd {
            let dirent = match res_dirent {
                Ok(dirent) => dirent,
                Err(e) => return Err(ReadDataDir { source: e }),
            };
            let path = dirent.path();
            if let Ok(file_type) = dirent.file_type() {
                if path.extension() == Some(OsStr::new("conf")) && file_type.is_file() {
                    let cfg_raw = Config::load_raw(path)?;
                    cfg.merge(cfg_raw);
                }
            }
        }

        Ok(cfg)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigLoadError> {
        let mut cfg = Config::default()?;
        let cfg_raw = Config::load_raw(path)?;
        cfg.merge(cfg_raw);
        Ok(cfg)
    }

    pub fn get_int(&self, section: &str, key: &str) -> Result<u64, ConfigGetIntError> {
        use self::ConfigGetIntError::*;

        match self.data.get(section) {
            Some(map) => match map.get(key) {
                Some(value) => Ok(u64::from_str(value)?),
                None => Err(NoKey),
            },
            None => Err(NoSection),
        }
    }

    pub fn get_float(&self, section: &str, key: &str) -> Result<f32, ConfigGetFloatError> {
        use self::ConfigGetFloatError::*;

        match self.data.get(section) {
            Some(map) => match map.get(key) {
                Some(value) => Ok(f32::from_str(value)?),
                None => Err(NoKey),
            },
            None => Err(NoSection),
        }
    }

    pub fn get_relative_time(
        &self,
        section: &str,
        key: &str,
    ) -> Result<time::Relative, ConfigGetRelativeTimeError> {
        use self::ConfigGetRelativeTimeError::*;

        match self.data.get(section) {
            Some(map) => match map.get(key) {
                Some(value) => Ok(time::Relative::from_str(value)?),
                None => Err(NoKey),
            },
            None => Err(NoSection),
        }
    }

    pub fn get_filename(
        &self,
        section: &str,
        key: &str,
    ) -> Result<PathBuf, ConfigGetFilenameError> {
        use self::ConfigGetFilenameError::*;

        match self.data.get(section) {
            Some(map) => match map.get(key) {
                Some(value) => {
                    let expanded = self.expand_dollar(value)?;
                    Ok(PathBuf::from(expanded))
                }
                None => Err(NoKey),
            },
            None => Err(NoSection),
        }
    }

    pub fn set_string(&mut self, section: &str, key: &str, mut value: String) -> Option<String> {
        let section: Cow<str> = Cow::Owned(section.to_owned());
        let key: Cow<str> = Cow::Owned(key.to_owned());

        if let Some(map) = self.data.get_mut(&*section) {
            if let Some(val) = map.get_mut(&*key) {
                std::mem::swap(val, &mut value);
                return Some(value);
            }
            map.insert(section.into_owned(), value);
            return None;
        }

        let mut map = HashMap::with_capacity(1);
        map.insert(key.into_owned(), value);
        self.data.insert(section.into_owned(), map);
        None
    }

    pub fn expand_dollar<'o>(&self, orig: &'o str) -> Result<String, ConfigExpandDollarError> {
        use self::ConfigExpandDollarError::*;

        let lookup = |name: &str| {
            use std::env::VarError;

            match self.data.get("PATHS").and_then(|m| m.get(name)) {
                Some(v) => Some(self.expand_dollar(v)),
                None => match std::env::var(name) {
                    Ok(s) => Some(self.expand_dollar(s.borrow())),
                    Err(e) => match e {
                        VarError::NotPresent => None,
                        VarError::NotUnicode(_) => Some(Err(NonUnicodeEnvVar {
                            var_name: name.to_string(),
                        })),
                    },
                },
            }
        };

        let mut ret = String::with_capacity(orig.len());
        let mut chars = orig.char_indices().peekable();

        while let Some((_, c)) = chars.next() {
            if c == '$' {
                if let Some(&(_, c)) = chars.peek() {
                    let get_name = |mut chars: std::iter::Peekable<std::str::CharIndices<'o>>| {
                        let start = match chars.peek() {
                            Some(&(start, _)) => start,
                            None => orig.len(),
                        };
                        loop {
                            if let Some(&(end, c)) = chars.peek() {
                                if !(c.is_alphanumeric() || c == '_') {
                                    let name = &orig[start..end];
                                    return (name, chars);
                                }
                                chars.next();
                            } else {
                                let name = &orig[start..];
                                return (name, chars);
                            }
                        }
                    };
                    if c == '{' {
                        chars.next();
                        if let Some(&(start, _)) = chars.peek() {
                            let (name, nchars) = get_name(chars);
                            chars = nchars;
                            if name.is_empty() {
                                // got something like "${_" where _ is not alphanumeric
                                return Err(Syntax { pos: start });
                            }
                            if let Some((pos, c)) = chars.next() {
                                match c {
                                    '}' => match lookup(name) {
                                        Some(expanded) => ret.push_str(expanded?.borrow()),
                                        None => {
                                            return Err(UnknownVariable {
                                                var_name: name.to_string(),
                                            })
                                        }
                                    },
                                    ':' => {
                                        if let Some((pos, c)) = chars.next() {
                                            if c != '-' {
                                                return Err(Syntax { pos });
                                            }
                                            if let Some(&(start, _)) = chars.peek() {
                                                let mut depth = 0usize;
                                                let end: usize;
                                                loop {
                                                    if let Some((e, c)) = chars.next() {
                                                        match c {
                                                            '{' => depth += 1,
                                                            '}' => {
                                                                if depth == 0 {
                                                                    end = e;
                                                                    break;
                                                                } else {
                                                                    depth -= 1;
                                                                }
                                                            }
                                                            _ => (),
                                                        }
                                                    } else {
                                                        return Err(UnclosedBraces);
                                                    }
                                                }
                                                if let Some(expanded) = lookup(name) {
                                                    // have "${name:-def}" and we were able to
                                                    // resolve `name` to `expanded`
                                                    ret.push_str(&(expanded?));
                                                } else {
                                                    // have "${name:-def}" and we were not able
                                                    // to resolve name
                                                    let def = &orig[start..end];
                                                    ret.push_str(&(self.expand_dollar(def))?);
                                                }
                                            } else {
                                                // string ended after "${name:-"
                                                return Err(UnclosedBraces);
                                            }
                                        } else {
                                            // string ended after "${name:"
                                            return Err(UnclosedBraces);
                                        }
                                    }
                                    _ => {
                                        // got string "${name_" where _ is an invalid character
                                        return Err(Syntax { pos });
                                    }
                                }
                            } else {
                                return Err(UnclosedBraces);
                            }
                        } else {
                            return Err(UnclosedBraces);
                        }
                    } else {
                        let (name, nchars) = get_name(chars);
                        chars = nchars;
                        match lookup(name) {
                            Some(expanded) => ret.push_str(expanded?.borrow()),
                            None => {
                                return Err(UnknownVariable {
                                    var_name: name.to_string(),
                                })
                            }
                        }
                    }
                } else {
                    return Err(Syntax { pos: orig.len() });
                }
            } else {
                ret.push(c);
            }
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    #[test]
    fn test_expand_dollar() {
        let mut cfg = Config::empty();

        let res = cfg.set_string("PATHS", "IN_PATHS", String::from("in_paths"));
        assert!(res.is_none());
        std::env::set_var("IN_ENV", "in_env");

        let unexpanded = "foo $IN_PATHS $IN_ENV ${NOT_ANYWHERE:-${IN_ENV}_wub}_blah";
        let expanded = cfg.expand_dollar(unexpanded).unwrap();
        assert_eq!(expanded, "foo in_paths in_env in_env_wub_blah");
    }
}
