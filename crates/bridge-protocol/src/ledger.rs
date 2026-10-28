use crate::envelope::{Envelope, ObservedEvent};
use crate::id::{
    BindingId, EventId, ProviderBotKey, ProviderEventKey, RegisteredBinding, TenantId,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureVerdict {
    Verified,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressReject {
    Signature,
    UnknownBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    BindingOwnedByOtherBot,
    BotOwnedByOtherBinding,
}

pub struct DeliveryLedger {
    by_bot: BTreeMap<String, RegisteredBinding>,
    by_provider: BTreeMap<ProviderEventKey, EventId>,
    by_event: BTreeMap<EventId, Envelope>,
    next_event: u64,
}

impl Default for DeliveryLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryLedger {
    pub fn new() -> Self {
        Self {
            by_bot: BTreeMap::new(),
            by_provider: BTreeMap::new(),
            by_event: BTreeMap::new(),
            next_event: 1,
        }
    }

    pub fn register_binding(
        &mut self,
        tenant: &str,
        binding_label: &str,
        provider_bot: &str,
    ) -> Result<RegisteredBinding, RegisterError> {
        if let Some(existing) = self.by_bot.get(provider_bot) {
            if existing.tenant_id().as_str() == tenant
                && existing.binding_id().as_str() == binding_label
            {
                return Ok(existing.clone());
            }
            return Err(RegisterError::BotOwnedByOtherBinding);
        }
        if self
            .by_bot
            .values()
            .any(|registered| registered.binding_id().as_str() == binding_label)
        {
            return Err(RegisterError::BindingOwnedByOtherBot);
        }
        let registered = RegisteredBinding::new(
            TenantId::new(tenant.to_owned()),
            BindingId::new(binding_label.to_owned()),
            ProviderBotKey::new(provider_bot.to_owned()),
        );
        self.by_bot
            .insert(provider_bot.to_owned(), registered.clone());
        Ok(registered)
    }

    pub fn binding_for_bot(&self, provider_bot: &str) -> Option<&RegisteredBinding> {
        self.by_bot.get(provider_bot)
    }

    pub fn accept(
        &mut self,
        binding: &RegisteredBinding,
        observed: &ObservedEvent,
        verdict: SignatureVerdict,
    ) -> Result<EventId, IngressReject> {
        match verdict {
            SignatureVerdict::Failed => return Err(IngressReject::Signature),
            SignatureVerdict::Verified => {}
        }
        if self.by_bot.get(binding.provider_bot().as_str()) != Some(binding) {
            return Err(IngressReject::UnknownBinding);
        }
        let key = ProviderEventKey::new(
            binding.binding_id().clone(),
            observed.platform_event_id.clone(),
        );
        if let Some(event_id) = self.by_provider.get(&key) {
            return Ok(*event_id);
        }
        let event_id = EventId::new(self.next_event);
        self.next_event = self
            .next_event
            .checked_add(1)
            .expect("event id space exhausted");
        let envelope = Envelope::new(event_id, key.clone(), binding.tenant_id().clone(), observed);
        self.by_provider.insert(key, event_id);
        self.by_event.insert(event_id, envelope);
        Ok(event_id)
    }

    pub fn admitted_count(&self) -> usize {
        self.by_event.len()
    }

    pub fn export_envelope(&self, event: EventId) -> Option<&Envelope> {
        self.by_event.get(&event)
    }
}
