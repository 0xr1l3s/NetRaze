//! RFC 4515 parsing is completed in the search phase.

use crate::message::Filter;

pub fn parse_filter(_input: &str) -> Result<Filter, String> {
    Err("RFC 4515 parser is not initialized".to_owned())
}
