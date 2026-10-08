use encoding_rs::{Decoder, DecoderResult, GBK};

use crate::codepage::{CodePage, TextError};
use crate::convert::decode;

enum DecoderKind {
    Cp437,
    Cp936(Decoder),
}

/// Stateful CP437/CP936 byte-stream decoder.
///
/// CP936 lead bytes are kept internally when a write ends between the two
/// bytes of one character. Call `push` with `final_chunk = true` exactly once
/// to finish the stream and detect a dangling final lead byte.
pub struct StreamDecoder {
    code_page: CodePage,
    decoder: DecoderKind,
    finished: bool,
    failed: bool,
}

impl StreamDecoder {
    pub fn new(code_page: CodePage) -> Self {
        let decoder = match code_page {
            CodePage::Cp437 => DecoderKind::Cp437,
            CodePage::Cp936 => DecoderKind::Cp936(GBK.new_decoder_without_bom_handling()),
        };
        Self {
            code_page,
            decoder,
            finished: false,
            failed: false,
        }
    }

    /// Decode the next stream chunk, retaining an incomplete CP936 lead byte.
    pub fn push(&mut self, bytes: &[u8], final_chunk: bool) -> Result<String, TextError> {
        if self.finished {
            return Err(TextError::StreamFinished);
        }
        if self.failed {
            return Err(TextError::StreamFailed);
        }

        match &mut self.decoder {
            DecoderKind::Cp437 => {
                let output = decode(bytes, self.code_page)?;
                if final_chunk {
                    self.finished = true;
                }
                Ok(output)
            }
            DecoderKind::Cp936(decoder) => {
                let capacity = decoder
                    .max_utf8_buffer_length_without_replacement(bytes.len())
                    .ok_or(TextError::OutputTooLarge)?;
                let mut output = String::new();
                output
                    .try_reserve(capacity.max(4))
                    .map_err(|_| TextError::AllocationFailed)?;
                let (result, read) =
                    decoder.decode_to_string_without_replacement(bytes, &mut output, final_chunk);
                match result {
                    DecoderResult::InputEmpty if read == bytes.len() => {
                        if final_chunk {
                            self.finished = true;
                        }
                        Ok(output)
                    }
                    DecoderResult::InputEmpty | DecoderResult::Malformed(_, _) => {
                        self.failed = true;
                        Err(TextError::MalformedInput {
                            code_page: self.code_page,
                            byte_index: None,
                        })
                    }
                    DecoderResult::OutputFull => {
                        self.failed = true;
                        Err(TextError::OutputTooLarge)
                    }
                }
            }
        }
    }
}
