//! Response rehydration — replaces pseudo-tokens back with original values.
//!
//! Handles both complete responses and SSE streaming chunks.

use crate::{RehydratedText, vault::Vault};
use anyhow::Result;

pub struct Rehydrator;

impl Rehydrator {
    /// Rehydrate a complete text response, replacing pseudo-tokens with originals.
    pub fn rehydrate(text: &str, vault: &Vault) -> Result<RehydratedText> {
        let mappings = vault.reverse_mappings();
        let mut result = text.to_string();
        let mut count = 0;

        // Sort mappings by token length (longest first) to avoid partial matches.
        // e.g., "ORG_12" should be replaced before "ORG_1"
        let mut sorted_mappings: Vec<_> = mappings.iter().collect();
        sorted_mappings.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        for (token, original) in sorted_mappings {
            if result.contains(token.as_str()) {
                result = result.replace(token.as_str(), original);
                count += 1;
            }
        }

        Ok(RehydratedText {
            text: result,
            rehydrated_count: count,
        })
    }

    /// Rehydrate a single SSE streaming chunk.
    /// Uses a token buffer to handle pseudo-tokens split across chunks.
    pub fn rehydrate_chunk(
        chunk: &str,
        buffer: &mut String,
        vault: &Vault,
    ) -> Result<(String, bool)> {
        buffer.push_str(chunk);

        // A pseudo-token is `CATEGORY_DIGITS` (e.g. ORG_7, PHONE_12). Across SSE
        // streaming a token can arrive split into several chunks
        // ("PH" -> "ONE" -> "_" -> "2"), so we must HOLD any trailing run that
        // could still grow into — or already is — a token: uppercase letters, an
        // optional underscore, and optional digits (`[A-Z]+(_\d*)?$`). Only the
        // text before that tail is safe to flush this tick; complete tokens in
        // the flushed prefix are rehydrated. The caller flushes the final tail
        // when the stream ends.
        let tail_re = regex::Regex::new(r"[A-Z]+(_\d*)?$")?;
        let hold_at = tail_re.find(buffer).map(|m| m.start()).unwrap_or(buffer.len());
        let flushable = buffer[..hold_at].to_string();
        let held = buffer[hold_at..].to_string();

        let token_re = regex::Regex::new(r"[A-Z]+_\d+")?;
        let mut any = false;
        let output = token_re
            .replace_all(&flushable, |caps: &regex::Captures| {
                match vault.lookup(&caps[0]) {
                    Some(original) => {
                        any = true;
                        original.to_string()
                    }
                    None => caps[0].to_string(),
                }
            })
            .into_owned();

        *buffer = held;
        Ok((output, any))
    }
}
