import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RefreshToken(Base):
    """
    Refresh tokens con ROTACIÓN y DETECCIÓN DE REUSO:
    - Cada uso entrega un token nuevo y revoca el anterior.
    - Todos los tokens de un mismo login comparten `family_id`.
    - Si alguien presenta un token ya revocado (señal de robo), se revoca la
      familia completa y se incrementa users.token_version.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)  # SHA-256 hex

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("refresh_tokens.id", ondelete="SET NULL"))

    # Auditoría
    created_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
