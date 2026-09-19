"""Agent runtime.

Holds no key. Proposes payments. Receives rejections as structured tool errors
and is expected to reason about them rather than retry blindly.

Assume this process is compromised. Nothing here is trusted.
"""


def fetch_paid_resource(url: str):
    """Tool exposed to the model.

    Flow:
      GET url
      if 402: parse payment requirements
              POST to policy engine for an authorisation
              on reject -> return the reason to the model as a tool error
              on allow  -> retry with X-PAYMENT header
      return the resource

    TODO(phase2)
    """
    raise NotImplementedError
