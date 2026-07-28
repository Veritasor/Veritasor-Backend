# Observability and Tracing

## Attestation Submissions

Batch-flush deadlines and queue waits are traced with dedicated OpenTelemetry spans. This allows developers to debug batch-window delays and trace errors related to batch composition.

### Spans
- `queue.enqueue`: Emitted when an attestation is added to the batch queue. Includes `user.id`, `business.id`, and `queue.size` attributes.
- `batch.flush`: Emitted when the queue is flushed (either by reaching max size or flush deadline). Includes `batch.size` attribute. Contains Span Links back to the `queue.enqueue` spans to associate child submissions with the batch process.
- `queue.dequeue`: Emitted for each individual submission from the batch. Includes `queue.wait_time_ms` indicating the duration an item spent waiting in the queue. Links to its parent `queue.enqueue` span.

### Attributes
- `queue.size`: The size of the batching queue when the item was enqueued.
- `queue.wait_time_ms`: The duration (in ms) the item waited in the queue before processing.
- `batch.size`: The number of items processed during a batch flush.
