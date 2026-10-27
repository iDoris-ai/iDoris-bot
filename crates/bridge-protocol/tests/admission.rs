use bridge_protocol::{
    Channel, Conversation, ConversationKind, CostClass, DeliveryLedger, IngressReject, Message,
    ObservedEvent, PaidPush, PlatformEventId, ProviderConversationId, ProviderSenderId,
    RegisterError, RegisteredBinding, ReplyWindow, SignatureVerdict, Timestamp, TraceId,
};

const OCCURRED_MS: i64 = 1_792_555_800_000;
const RECEIVED_MS: i64 = 1_792_555_801_000;
const REPLY_DEADLINE_MS: i64 = 1_792_555_860_000;

fn bakery(platform_event: &str) -> ObservedEvent {
    ObservedEvent {
        platform_event_id: PlatformEventId::new(platform_event.to_owned()),
        channel: Channel::Line,
        occurred_at: Timestamp::unix_millis(OCCURRED_MS),
        received_at: Timestamp::unix_millis(RECEIVED_MS),
        conversation: Conversation {
            provider_conversation_id: ProviderConversationId::new("room-1".to_owned()),
            kind: ConversationKind::Direct,
            sender_provider_id: ProviderSenderId::new("user-1".to_owned()),
        },
        message: Message::Text("还有法棍吗？".to_owned()),
        reply_deadline: Timestamp::unix_millis(REPLY_DEADLINE_MS),
        trace_id: TraceId::new("trace-1".to_owned()),
    }
}

fn admit(
    ledger: &mut DeliveryLedger,
    binding: &RegisteredBinding,
    observed: &ObservedEvent,
) -> bridge_protocol::EventId {
    match ledger.accept(binding, observed, SignatureVerdict::Verified) {
        Ok(event) => event,
        Err(reject) => panic!("verified accept rejected: {reject:?}"),
    }
}

#[test]
fn same_labels_return_the_same_binding() {
    let mut ledger = DeliveryLedger::new();
    let first = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    let second = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    assert_eq!(first.binding_id(), second.binding_id());
    assert_eq!(first.tenant_id(), second.tenant_id());
    assert_eq!(
        ledger
            .binding_for_bot("line-bot-U1")
            .map(RegisteredBinding::binding_id),
        Some(first.binding_id())
    );
    assert_eq!(
        ledger
            .binding_for_bot("line-bot-U1")
            .map(RegisteredBinding::tenant_id),
        Some(first.tenant_id())
    );
}

#[test]
fn conflicting_bot_or_label_is_rejected() {
    let mut ledger = DeliveryLedger::new();
    let first = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    assert_eq!(
        ledger.register_binding("org-a", "bind-b", "line-bot-U1"),
        Err(RegisterError::BotOwnedByOtherBinding)
    );
    assert_eq!(
        ledger.register_binding("org-a", "bind-a", "line-bot-U2"),
        Err(RegisterError::BindingOwnedByOtherBot)
    );
    let again = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    assert_eq!(again.binding_id(), first.binding_id());
    assert_eq!(again.tenant_id(), first.tenant_id());
}

#[test]
fn foreign_binding_is_not_admitted() {
    let mut other = DeliveryLedger::new();
    let foreign = other
        .register_binding("org-z", "bind-z", "line-bot-Z")
        .unwrap();
    let mut ledger = DeliveryLedger::new();
    let observed = bakery("wh-x");
    assert_eq!(
        ledger.accept(&foreign, &observed, SignatureVerdict::Failed),
        Err(IngressReject::Signature)
    );
    assert_eq!(ledger.admitted_count(), 0);
    assert_eq!(
        ledger.accept(&foreign, &observed, SignatureVerdict::Verified),
        Err(IngressReject::UnknownBinding)
    );
    assert_eq!(ledger.admitted_count(), 0);
}

#[test]
fn failed_signature_admits_nothing_then_verified_keeps_the_text() {
    let mut ledger = DeliveryLedger::new();
    let binding = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    let observed = bakery("wh-1");
    assert_eq!(
        ledger.accept(&binding, &observed, SignatureVerdict::Failed),
        Err(IngressReject::Signature)
    );
    assert_eq!(ledger.admitted_count(), 0);
    let event = admit(&mut ledger, &binding, &observed);
    assert_eq!(
        ledger.export_envelope(event).unwrap().message(),
        &Message::Text("还有法棍吗？".to_owned())
    );
}

#[test]
fn verified_replay_returns_the_same_event() {
    let mut ledger = DeliveryLedger::new();
    let binding = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    let observed = bakery("wh-1");
    let first = admit(&mut ledger, &binding, &observed);
    let second = admit(&mut ledger, &binding, &observed);
    assert_eq!(second, first);
    assert_eq!(ledger.admitted_count(), 1);
}

#[test]
fn second_binding_same_platform_event_is_a_different_event() {
    let mut ledger = DeliveryLedger::new();
    let first_binding = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    let second_binding = ledger
        .register_binding("org-b", "bind-b", "line-bot-U2")
        .unwrap();
    let observed = bakery("wh-1");
    let first = admit(&mut ledger, &first_binding, &observed);
    let second = admit(&mut ledger, &second_binding, &observed);
    assert_ne!(first, second);
    assert_ne!(
        ledger.export_envelope(first).unwrap().provider_event_key(),
        ledger.export_envelope(second).unwrap().provider_event_key()
    );
    assert_eq!(ledger.admitted_count(), 2);
}

#[test]
fn fresh_envelope_is_denied_and_unmetered() {
    let mut ledger = DeliveryLedger::new();
    let binding = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    let event = admit(&mut ledger, &binding, &bakery("wh-1"));
    let exported = ledger.export_envelope(event).unwrap();
    assert_eq!(exported.schema(), "sns-bridge/1");
    assert_eq!(exported.tenant_id(), binding.tenant_id());
    assert_eq!(exported.binding_id(), binding.binding_id());
    assert_eq!(exported.paid_push(), &PaidPush::Denied);
    assert_eq!(exported.cost_class(), CostClass::None);
    assert_eq!(
        exported.reply_window(),
        ReplyWindow::Open {
            deadline: Timestamp::unix_millis(REPLY_DEADLINE_MS),
        }
    );
}
