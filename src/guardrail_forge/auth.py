import hmac

from fastapi import Depends, Header, HTTPException, status

from guardrail_forge.config import Settings, get_settings


def require_api_key(
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    if settings.api_key and (not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

