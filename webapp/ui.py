import datetime
from datetime import timedelta
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")


def format_dt_plus3(value: datetime.datetime | None, fmt: str = "%H:%M • %d.%m.%Y") -> str:
    if not value:
        return ""
    return (value + timedelta(hours=3)).strftime(fmt)


def iso_dt_plus3(value: datetime.datetime | None) -> str:
    if not value:
        return ""
    return (value + timedelta(hours=3)).isoformat()


templates.env.globals["format_dt_plus3"] = format_dt_plus3
templates.env.globals["iso_dt_plus3"] = iso_dt_plus3
