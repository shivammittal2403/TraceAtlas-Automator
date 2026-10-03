# Data handling and retention

Capture only approved/public/authorized records necessary for the case
purpose. Person/company input uses public case-local IDs; the new collector adds
no email/phone/private-account discovery. Credentials belong in approved secret
references, not source URIs, envelopes or tool arguments.

Evidence metadata inherits the registered retention policy and case-member access
label. These labels are metadata, not new automatic erasure/encryption/KMS
implementation. Local OS permissions and operator handling remain necessary.
Source body minimization and legal-hold/retention execution need separate policy
work; no real personal dataset is committed in the golden pack.
