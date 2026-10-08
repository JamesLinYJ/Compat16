//! SDK OLESERVER/OLESERVERDOC callback slot contracts.
//!
//! FAR pointers remain guest values. The HGLOBAL arguments in the SDK
//! prototypes are Win16 HANDLE/WORD values, not host addresses.

use super::far_callback::{Win16FarCallbackArgument as Arg, Win16FarCallbackReturn};
use win16_abi::Access;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerCallbackMethod {
    Open,
    Create,
    CreateFromTemplate,
    Edit,
    Exit,
    Release,
    Execute,
}

impl ServerCallbackMethod {
    pub(super) const fn vtable_slot(self) -> u32 {
        match self {
            Self::Open => 0,
            Self::Create => 1,
            Self::CreateFromTemplate => 2,
            Self::Edit => 3,
            Self::Exit => 4,
            Self::Release => 5,
            Self::Execute => 6,
        }
    }

    pub(super) const fn vtable_slots() -> u32 {
        7
    }

    pub(super) const fn callback_return(self) -> Win16FarCallbackReturn {
        Win16FarCallbackReturn::Word
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerCallbackArguments {
    Open {
        server_far: u32,
        document_handle: u32,
        document_name_far: u32,
        document_output_far: u32,
    },
    Create {
        server_far: u32,
        document_handle: u32,
        class_name_far: u32,
        document_name_far: u32,
        document_output_far: u32,
    },
    CreateFromTemplate {
        server_far: u32,
        document_handle: u32,
        class_name_far: u32,
        document_name_far: u32,
        template_name_far: u32,
        document_output_far: u32,
    },
    Edit {
        server_far: u32,
        document_handle: u32,
        class_name_far: u32,
        document_name_far: u32,
        document_output_far: u32,
    },
    Exit {
        server_far: u32,
    },
    Release {
        server_far: u32,
    },
    Execute {
        server_far: u32,
        command_hglobal: u16,
    },
}

impl ServerCallbackArguments {
    pub(super) const fn method(self) -> ServerCallbackMethod {
        match self {
            Self::Open { .. } => ServerCallbackMethod::Open,
            Self::Create { .. } => ServerCallbackMethod::Create,
            Self::CreateFromTemplate { .. } => ServerCallbackMethod::CreateFromTemplate,
            Self::Edit { .. } => ServerCallbackMethod::Edit,
            Self::Exit { .. } => ServerCallbackMethod::Exit,
            Self::Release { .. } => ServerCallbackMethod::Release,
            Self::Execute { .. } => ServerCallbackMethod::Execute,
        }
    }

    pub(super) const fn callback_return(self) -> Win16FarCallbackReturn {
        self.method().callback_return()
    }

    pub(super) fn encode(self) -> Vec<Arg> {
        let read_pointer = |far| Arg::GuestPointer {
            far,
            access: Access::Read,
            bytes: 4,
        };
        let output_pointer = |far| Arg::GuestPointer {
            far,
            access: Access::Write,
            bytes: 4,
        };
        match self {
            Self::Open {
                server_far,
                document_handle,
                document_name_far,
                document_output_far,
            } => vec![
                read_pointer(server_far),
                Arg::Dword(document_handle),
                read_pointer(document_name_far),
                output_pointer(document_output_far),
            ],
            Self::Create {
                server_far,
                document_handle,
                class_name_far,
                document_name_far,
                document_output_far,
            } => vec![
                read_pointer(server_far),
                Arg::Dword(document_handle),
                read_pointer(class_name_far),
                read_pointer(document_name_far),
                output_pointer(document_output_far),
            ],
            Self::CreateFromTemplate {
                server_far,
                document_handle,
                class_name_far,
                document_name_far,
                template_name_far,
                document_output_far,
            } => vec![
                read_pointer(server_far),
                Arg::Dword(document_handle),
                read_pointer(class_name_far),
                read_pointer(document_name_far),
                read_pointer(template_name_far),
                output_pointer(document_output_far),
            ],
            Self::Edit {
                server_far,
                document_handle,
                class_name_far,
                document_name_far,
                document_output_far,
            } => vec![
                read_pointer(server_far),
                Arg::Dword(document_handle),
                read_pointer(class_name_far),
                read_pointer(document_name_far),
                output_pointer(document_output_far),
            ],
            Self::Exit { server_far } | Self::Release { server_far } => {
                vec![read_pointer(server_far)]
            }
            Self::Execute {
                server_far,
                command_hglobal,
            } => vec![read_pointer(server_far), Arg::Word(command_hglobal)],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerDocumentCallbackMethod {
    Close,
    Release,
    Execute,
}

impl ServerDocumentCallbackMethod {
    pub(super) const fn vtable_slot(self) -> u32 {
        match self {
            Self::Close => 1,
            Self::Release => 5,
            Self::Execute => 7,
        }
    }

    // Validate the complete SDK table even though only three document
    // callbacks currently have executable protocol routes.
    pub(super) const fn vtable_slots() -> u32 {
        8
    }

    pub(super) const fn callback_return(self) -> Win16FarCallbackReturn {
        Win16FarCallbackReturn::Word
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerDocumentCallbackArguments {
    Close {
        server_document_far: u32,
    },
    Release {
        server_document_far: u32,
    },
    Execute {
        server_document_far: u32,
        command_hglobal: u16,
    },
}

impl ServerDocumentCallbackArguments {
    pub(super) const fn method(self) -> ServerDocumentCallbackMethod {
        match self {
            Self::Close { .. } => ServerDocumentCallbackMethod::Close,
            Self::Release { .. } => ServerDocumentCallbackMethod::Release,
            Self::Execute { .. } => ServerDocumentCallbackMethod::Execute,
        }
    }

    pub(super) const fn callback_return(self) -> Win16FarCallbackReturn {
        self.method().callback_return()
    }

    pub(super) fn encode(self) -> Vec<Arg> {
        let read_pointer = |far| Arg::GuestPointer {
            far,
            access: Access::Read,
            bytes: 4,
        };
        match self {
            Self::Close {
                server_document_far,
            }
            | Self::Release {
                server_document_far,
            } => vec![read_pointer(server_document_far)],
            Self::Execute {
                server_document_far,
                command_hglobal,
            } => vec![
                read_pointer(server_document_far),
                Arg::Word(command_hglobal),
            ],
        }
    }
}
