# Bounded execution and accounting

Existing task budget is USD 1, 120 seconds, eight tool attempts and two
model calls. The new runner makes zero model/paid connector calls, reserves no
external spend and reports zero model cost. Anonymous provider terms are still an
operator entitlement responsibility.

Actual network attempts, including retries, share the eight-attempt cap before
dispatch. Runtime/deadline is checked per request and at service completion.
Source documents cap at eight and 512 KiB each; analysis caps at 200 facts.
Storage/CPU/egress dollars are not measured. Paid connectors/models require cost
reservations and unknown-charge reconciliation before autonomy is enabled.
