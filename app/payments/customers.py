"""
Cliente del proveedor y guardado de tarjeta (sección 2 del doc de pagos).

La tarjeta viaja de la app al proveedor con su componente oficial (PaymentSheet en Flutter,
Payment Element en web): nuestra API solo entrega el client_secret de un SetupIntent y, al
listar, marca + últimos 4 dígitos + vencimiento. Así la plataforma queda en PCI SAQ A.
El client_secret se entrega solo al dueño y nunca se registra (el filtro de logs lo enmascara).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import PaymentCustomer, User
from app.payments.providers.base import PaymentProvider, SavedCard, SetupIntentInfo


def ensure_customer(db: Session, user: User, provider: PaymentProvider) -> PaymentCustomer:
    row = db.get(PaymentCustomer, (user.id, provider.name))
    if row is not None:
        return row
    # La creación en el proveedor es idempotente por usuario; ON CONFLICT cubre dos peticiones simultáneas.
    customer_id = provider.create_customer(user.id, user.email, user.full_name)
    db.execute(insert(PaymentCustomer).values(user_id=user.id, provider=provider.name,
                                              provider_customer_id=customer_id)
               .on_conflict_do_nothing(index_elements=["user_id", "provider"]))
    db.flush()
    return db.scalar(select(PaymentCustomer).where(PaymentCustomer.user_id == user.id,
                                                   PaymentCustomer.provider == provider.name))


def start_card_setup(db: Session, user: User, provider: PaymentProvider) -> SetupIntentInfo:
    customer = ensure_customer(db, user, provider)
    return provider.create_setup_intent(customer.provider_customer_id, user.id)


def saved_cards(db: Session, user: User, provider: PaymentProvider) -> list[SavedCard]:
    row = db.get(PaymentCustomer, (user.id, provider.name))
    if row is None:
        return []
    return provider.list_saved_cards(row.provider_customer_id)
