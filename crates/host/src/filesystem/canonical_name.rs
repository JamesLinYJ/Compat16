//! Project an existing component into the same DOS alias namespace as FindFirst.
use super::{Filesystem, decode};
use dos_kernel::{DosErrorCode, DosHostError};

impl Filesystem {
    pub(crate) fn project_short_component(
        &mut self,
        parent: &[u8],
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, DosHostError> {
        let result = self.existing_short_component(parent, name);
        match result {
            Err(error)
                if matches!(
                    error.code,
                    DosErrorCode::FileNotFound | DosErrorCode::PathNotFound
                ) =>
            {
                Ok(None)
            }
            result => result,
        }
    }

    fn existing_short_component(
        &mut self,
        parent: &[u8],
        name: &[u8],
    ) -> Result<Option<Vec<u8>>, DosHostError> {
        let name = decode(name, self.code_page)?;
        // One literal name only: never let a component reach a native path or
        // wildcard namespace. DOS reports its own lexical error on None.
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.chars().any(|c| {
                c < ' ' || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
            })
        {
            return Ok(None);
        }
        let parent = self.resolve_path(parent, true)?;
        let actual = self.resolve_dos_path_component(&parent, &name)?;
        let alias = self
            .aliases_for(&parent)?
            .by_real_name
            .get(&actual)
            .cloned();
        alias
            .map(|name| crate::windows::encode(&name, self.code_page))
            .transpose()
    }
}
