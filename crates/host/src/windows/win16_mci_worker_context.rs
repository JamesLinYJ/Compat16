//! Constructor for the native worker's owned call context.

use super::{MciNativeContext, WorkerThreadState};
use std::sync::Arc;

impl MciNativeContext {
    pub(super) fn new(state: Arc<WorkerThreadState>) -> Self {
        Self { state }
    }
}
