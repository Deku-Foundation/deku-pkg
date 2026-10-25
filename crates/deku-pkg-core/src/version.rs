//! Deku's native package-version ordering.
//!
//! Grammar: [epoch:]upstream[-release]. Epoch defaults to zero and release
//! defaults to "0". Comparison is deterministic and RPM-inspired: numeric
//! runs compare numerically, alphabetic runs compare lexically, and '~' sorts
//! before the corresponding base version (pre-release marker). Other
//! punctuation separates runs. This does not claim RPM, Debian, XBPS, or
//! SemVer compatibility.

use std::cmp::Ordering;

/// Parsed, comparable Deku package version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DekuVersion {
    epoch: u64,
    upstream: String,
    release: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionError {
    Empty,
    InvalidEpoch,
    InvalidUpstream,
    InvalidRelease,
    InvalidCharacter(char),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VersionError {}

fn valid_part(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-~".contains(&byte))
}

impl DekuVersion {
    /// Parse a package version. Non-zero epochs are written as N:.
    ///
    /// Leading zeroes in explicit epochs are rejected to avoid multiple
    /// strings representing the same identity. Versions without a release
    /// receive the canonical release "0".
    pub fn parse(value: &str) -> Result<Self, VersionError> {
        if value.is_empty() || value.trim() != value {
            return Err(VersionError::Empty);
        }

        let (epoch, body) = match value.split_once(':') {
            Some((epoch_text, rest)) => {
                if epoch_text.is_empty()
                    || !epoch_text.bytes().all(|byte| byte.is_ascii_digit())
                    || (epoch_text.len() > 1 && epoch_text.starts_with('0'))
                {
                    return Err(VersionError::InvalidEpoch);
                }
                let epoch = epoch_text
                    .parse::<u64>()
                    .map_err(|_| VersionError::InvalidEpoch)?;
                if rest.contains(':') {
                    return Err(VersionError::InvalidUpstream);
                }
                (epoch, rest)
            }
            None => {
                if value.contains(':') {
                    return Err(VersionError::InvalidEpoch);
                }
                (0, value)
            }
        };

        let (upstream, release) = match body.rsplit_once('-') {
            Some((upstream, release)) => (upstream, release),
            None => (body, "0"),
        };

        if !valid_part(upstream) {
            if let Some(ch) = upstream
                .chars()
                .find(|ch| !ch.is_ascii_alphanumeric() && !("._+-~".contains(*ch)))
            {
                return Err(VersionError::InvalidCharacter(ch));
            }
            return Err(VersionError::InvalidUpstream);
        }
        if !valid_part(release) {
            if let Some(ch) = release
                .chars()
                .find(|ch| !ch.is_ascii_alphanumeric() && !("._+-~".contains(*ch)))
            {
                return Err(VersionError::InvalidCharacter(ch));
            }
            return Err(VersionError::InvalidRelease);
        }

        Ok(Self {
            epoch,
            upstream: upstream.to_string(),
            release: release.to_string(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    /// A canonical rendering: omit the zero epoch and always include release.
    pub fn canonical(&self) -> String {
        let epoch = if self.epoch == 0 {
            String::new()
        } else {
            format!("{}:", self.epoch)
        };
        format!("{epoch}{}-{}", self.upstream, self.release)
    }

    pub fn compare(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| compare_part(&self.upstream, &other.upstream))
            .then_with(|| compare_part(&self.release, &other.release))
    }
}

impl std::fmt::Display for DekuVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl Ord for DekuVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

impl PartialOrd for DekuVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compare version components in runs. Separators other than '~' are ignored;
/// numeric runs sort after alphabetic runs and compare without overflow.
fn compare_part(left: &str, right: &str) -> Ordering {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let (mut i, mut j) = (0, 0);

    loop {
        if left.get(i) == Some(&b'~') || right.get(j) == Some(&b'~') {
            match (left.get(i) == Some(&b'~'), right.get(j) == Some(&b'~')) {
                (true, true) => {
                    i += 1;
                    j += 1;
                    continue;
                }
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                (false, false) => unreachable!(),
            }
        }

        while i < left.len() && !left[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < right.len() && !right[j].is_ascii_alphanumeric() {
            j += 1;
        }

        if i == left.len() || j == right.len() {
            return match (i == left.len(), j == right.len()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => unreachable!(),
            };
        }

        let left_numeric = left[i].is_ascii_digit();
        let right_numeric = right[j].is_ascii_digit();
        if left_numeric != right_numeric {
            return if left_numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let start_i = i;
        let start_j = j;
        if left_numeric {
            while i < left.len() && left[i].is_ascii_digit() {
                i += 1;
            }
            while j < right.len() && right[j].is_ascii_digit() {
                j += 1;
            }

            let mut left_number = &left[start_i..i];
            let mut right_number = &right[start_j..j];
            while left_number.first() == Some(&b'0') {
                left_number = &left_number[1..];
            }
            while right_number.first() == Some(&b'0') {
                right_number = &right_number[1..];
            }

            let ordering = left_number
                .len()
                .cmp(&right_number.len())
                .then_with(|| left_number.cmp(right_number));
            if ordering != Ordering::Equal {
                return ordering;
            }
        } else {
            while i < left.len() && left[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < right.len() && right[j].is_ascii_alphabetic() {
                j += 1;
            }
            let ordering = left[start_i..i].cmp(&right[start_j..j]);
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(input: &str) -> DekuVersion {
        DekuVersion::parse(input).expect("valid version fixture")
    }

    #[test]
    fn compares_epoch_before_version_and_release() {
        assert!(version("1:1.0-1") > version("99.0-99"));
        assert!(version("1.0-2") > version("1.0-1"));
        assert!(version("1.1-0") > version("1.0-99"));
    }

    #[test]
    fn compares_numeric_runs_numerically_without_integer_overflow() {
        assert!(version("1.10-1") > version("1.9-99"));
        assert!(
            version("1.999999999999999999999999999999-1")
                > version("1.100000000000000000000000000000-1")
        );
    }

    #[test]
    fn tilde_pre_release_sorts_before_base_release() {
        assert!(version("2.0~rc1-1") < version("2.0-1"));
        assert!(version("2.0~rc2-1") > version("2.0~rc1-1"));
        assert!(version("2.0~~snapshot-1") < version("2.0~rc1-1"));
    }

    #[test]
    fn punctuation_separates_runs_and_leading_zeroes_are_numeric() {
        assert_eq!(version("1.01-1"), version("1.1-1"));
        assert_eq!(version("1_2-1"), version("1.2-1"));
    }

    #[test]
    fn missing_release_defaults_to_zero_and_canonical_form_is_stable() {
        assert_eq!(version("1.2").canonical(), "1.2-0");
        assert_eq!(version("0:1.2-0"), version("1.2"));
        assert_eq!(version("3:1.2-4").canonical(), "3:1.2-4");
    }

    #[test]
    fn rejects_noncanonical_or_malformed_epochs() {
        for invalid in [
            "",
            " 1.0",
            "01:1.0",
            ":1.0",
            "18446744073709551616:1.0",
            "1:2:3",
        ] {
            assert!(DekuVersion::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn rejects_empty_parts_whitespace_and_non_ascii() {
        for invalid in ["-1", "1-", "1.0- ", "1.0-1 ", "1.0-β", "1.0/slash"] {
            assert!(DekuVersion::parse(invalid).is_err(), "{invalid}");
        }
    }
}
