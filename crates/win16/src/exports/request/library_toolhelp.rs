//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16LibraryToolhelpRequest {
    /// TOOLHELP global entry point: convert a guest global handle to its
    /// selector. The API returns a WORD selector or zero on failure.
    ToolhelpGlobalHandleToSel { handle: u16 },

    /// Retrieve the first global heap entry. `output` is an untouched guest
    /// FAR pointer; the runtime validates GLOBALENTRY16 before accessing it.
    ToolhelpGlobalFirst { output: u32, flags: u16 },

    /// Retrieve the next global heap entry into a raw guest FAR buffer.
    ToolhelpGlobalNext { output: u32, flags: u16 },

    /// Retrieve global heap information into a raw guest FAR buffer.
    ToolhelpGlobalInfo { output: u32 },

    /// Retrieve a global entry by handle into a raw guest FAR buffer.
    ToolhelpGlobalEntryHandle { output: u32, handle: u16 },

    /// Retrieve a module segment entry into a raw guest FAR buffer.
    ToolhelpGlobalEntryModule {
        output: u32,
        module: u16,
        segment: u16,
    },
}
