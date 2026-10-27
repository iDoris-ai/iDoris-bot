use crate::id::{
    BindingId, EventId, PlatformEventId, ProviderConversationId, ProviderEventKey,
    ProviderSenderId, TenantId, Timestamp, TraceId,
};

pub const SCHEMA: &str = "sns-bridge/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Line,
    Telegram,
    WhatsApp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationKind {
    Direct,
    Group,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub provider_conversation_id: ProviderConversationId,
    pub kind: ConversationKind,
    pub sender_provider_id: ProviderSenderId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedEvent {
    pub platform_event_id: PlatformEventId,
    pub channel: Channel,
    pub occurred_at: Timestamp,
    pub received_at: Timestamp,
    pub conversation: Conversation,
    pub message: Message,
    pub reply_deadline: Timestamp,
    pub trace_id: TraceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyWindow {
    Open { deadline: Timestamp },
    Closed { deadline: Timestamp },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostClass {
    None,
    PlatformMetered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidPushGrant {
    _private: (),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaidPush {
    Denied,
    Granted(PaidPushGrant),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponsePolicy {
    reply: ReplyWindow,
    paid_push: PaidPush,
}

impl ResponsePolicy {
    pub(crate) fn fresh(deadline: Timestamp) -> Self {
        Self {
            reply: ReplyWindow::Open { deadline },
            paid_push: PaidPush::Denied,
        }
    }

    pub fn reply_window(&self) -> ReplyWindow {
        self.reply
    }

    pub fn paid_push(&self) -> &PaidPush {
        &self.paid_push
    }

    pub fn cost_class(&self) -> CostClass {
        match self.paid_push {
            PaidPush::Denied => CostClass::None,
            PaidPush::Granted(_) => CostClass::PlatformMetered,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    event_id: EventId,
    provider_event_key: ProviderEventKey,
    tenant_id: TenantId,
    channel: Channel,
    occurred_at: Timestamp,
    received_at: Timestamp,
    conversation: Conversation,
    message: Message,
    response_policy: ResponsePolicy,
    trace_id: TraceId,
}

impl Envelope {
    pub(crate) fn new(
        event_id: EventId,
        provider_event_key: ProviderEventKey,
        tenant_id: TenantId,
        observed: &ObservedEvent,
    ) -> Self {
        Self {
            event_id,
            provider_event_key,
            tenant_id,
            channel: observed.channel,
            occurred_at: observed.occurred_at,
            received_at: observed.received_at,
            conversation: observed.conversation.clone(),
            message: observed.message.clone(),
            response_policy: ResponsePolicy::fresh(observed.reply_deadline),
            trace_id: observed.trace_id.clone(),
        }
    }

    pub fn schema(&self) -> &'static str {
        SCHEMA
    }

    pub fn event_id(&self) -> EventId {
        self.event_id
    }

    pub fn provider_event_key(&self) -> &ProviderEventKey {
        &self.provider_event_key
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn binding_id(&self) -> &BindingId {
        self.provider_event_key.binding_id()
    }

    pub fn channel(&self) -> Channel {
        self.channel
    }

    pub fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    pub fn received_at(&self) -> Timestamp {
        self.received_at
    }

    pub fn conversation(&self) -> &Conversation {
        &self.conversation
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn response_policy(&self) -> &ResponsePolicy {
        &self.response_policy
    }

    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    pub fn paid_push(&self) -> &PaidPush {
        self.response_policy.paid_push()
    }

    pub fn cost_class(&self) -> CostClass {
        self.response_policy.cost_class()
    }

    pub fn reply_window(&self) -> ReplyWindow {
        self.response_policy.reply_window()
    }
}
