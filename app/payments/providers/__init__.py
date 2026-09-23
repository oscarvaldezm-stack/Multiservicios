"""Selección del proveedor de pagos según la configuración (un solo objeto por proceso)."""
from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.payments.providers.base import PaymentProvider, ProviderError


@lru_cache
def get_provider() -> PaymentProvider:
    s = get_settings()
    if s.PAYMENT_PROVIDER_BACKEND == "stripe":
        from app.payments.providers.stripe_provider import StripePaymentProvider

        return StripePaymentProvider(s)
    if s.is_production:            # la configuración ya lo impide; segunda barrera
        raise ProviderError("Proveedor de pruebas en producción", code="PAYMENT_PROVIDER_MISCONFIGURED")
    from app.payments.providers.fake import FakePaymentProvider

    return FakePaymentProvider()


__all__ = ["PaymentProvider", "ProviderError", "get_provider"]
