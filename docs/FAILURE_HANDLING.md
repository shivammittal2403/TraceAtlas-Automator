# Failure behavior

Malformed schemas, wrong scope, stale authority and kill switch fail closed.
Provider shape/target/transport/rate failures use stable reason codes; successful
other sources remain in a PARTIAL product. Retries use existing bounded retry
policy and shared deadline. Three existing health failures suppress dispatch.

Completed-task retry returns the immutable product. Raw capture and indexes may
be partially written before a failed result; terminal result/product/state commit
atomically. There is no new failed-task resume, fenced distributed worker, outbox
or lease recovery. Create a new approved task and retain prior evidence instead
of deleting records to force a retry. Replay version/tamper failure is an error,
not a silently recomputed success.
