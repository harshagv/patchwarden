"""White-label: a team's own name, colour, logo and footer on the reports and emails its sites get."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import Organization, Site

DEFAULT = {"name": "Patchwarden", "color": "#c2410c", "logo_url": None, "footer": None}


def brand_for(db: Session, site: Site) -> dict:
    org = db.get(Organization, site.org_id) if site.org_id else None
    if org is None:
        return dict(DEFAULT)
    return {"name": org.brand_name or DEFAULT["name"], "color": org.brand_color or DEFAULT["color"],
            "logo_url": org.brand_logo_url, "footer": org.brand_footer}


def footer_text(brand: dict) -> str:
    return f"\n\n{brand['footer']}" if brand.get("footer") else ""
