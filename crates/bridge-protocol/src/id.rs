use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId(String);

impl BindingId {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(u64);

impl EventId {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event:{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlatformEventId(String);

impl PlatformEventId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderBotKey(String);

impl ProviderBotKey {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderEventKey {
    binding_id: BindingId,
    platform_event_id: PlatformEventId,
}

impl ProviderEventKey {
    pub(crate) fn new(binding_id: BindingId, platform_event_id: PlatformEventId) -> Self {
        Self {
            binding_id,
            platform_event_id,
        }
    }

    pub fn binding_id(&self) -> &BindingId {
        &self.binding_id
    }

    pub fn platform_event_id(&self) -> &PlatformEventId {
        &self.platform_event_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TraceId(String);

impl TraceId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProviderConversationId(String);

impl ProviderConversationId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProviderSenderId(String);

impl ProviderSenderId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const fn unix_millis(value: i64) -> Self {
        Self(value)
    }

    pub const fn unix_millis_value(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredBinding {
    tenant_id: TenantId,
    binding_id: BindingId,
    provider_bot: ProviderBotKey,
}

impl RegisteredBinding {
    pub(crate) fn new(
        tenant_id: TenantId,
        binding_id: BindingId,
        provider_bot: ProviderBotKey,
    ) -> Self {
        Self {
            tenant_id,
            binding_id,
            provider_bot,
        }
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn binding_id(&self) -> &BindingId {
        &self.binding_id
    }

    pub fn provider_bot(&self) -> &ProviderBotKey {
        &self.provider_bot
    }
}
