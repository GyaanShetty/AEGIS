"""x402-gated resource server — the counterparty being paid.

Two things are easy to get wrong here and both lose money:
  - idempotency: the same authorisation nonce must never settle twice
  - refunds: if settlement succeeds but the resource fails to generate, that is
    a refund case. Handle it explicitly; do not silently keep the payment.
"""


def payment_requirements(resource: str) -> dict:
    """402 body: scheme, network, asset, amount, payTo, nonce, validBefore,
    maxTimeoutSeconds.

    TODO(phase2)
    """
    raise NotImplementedError
