macro_rules! string_id {
    ($vis:vis $name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            $vis fn new(value: String) -> Self {
                Self(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(pub(crate) TenantId);
string_id!(pub(crate) BindingId);
string_id!(pub(crate) ProviderBotKey);
string_id!(pub PlatformEventId);
string_id!(pub TraceId);
string_id!(pub ProviderConversationId);
string_id!(pub ProviderSenderId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(u64);

impl EventId {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
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
