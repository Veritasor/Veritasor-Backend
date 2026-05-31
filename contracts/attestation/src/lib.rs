#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationExpiryExtended {
    pub new_expiry: u64,
}

pub struct Contract {
    pub current_expiry: u64,
    pub events: Vec<AttestationExpiryExtended>,
}

impl Contract {
    pub fn new(initial_expiry: u64) -> Self {
        Self {
            current_expiry: initial_expiry,
            events: Vec::new(),
        }
    }

    /// Extends the expiry of the attestation.
    /// Enforces two boundary panics:
    /// - new_expiry > current_expiry
    /// - new_expiry > timestamp
    pub fn extend_expiry(&mut self, timestamp: u64, new_expiry: u64) {
        if new_expiry <= self.current_expiry {
            panic!("new_expiry must be strictly greater than current_expiry");
        }
        if new_expiry <= timestamp {
            panic!("new_expiry must be strictly greater than timestamp");
        }

        self.current_expiry = new_expiry;
        self.events.push(AttestationExpiryExtended { new_expiry });
    }
}

#[cfg(test)]
mod extend_expiry_test;
