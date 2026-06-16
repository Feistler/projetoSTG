"""Agregacao de todos os conectores das 6 categorias.

``ALL_CONNECTORS`` e a fonte unica consumida pelo registro (stg.core.registry).
Para adicionar uma ferramenta nova: crie o conector na subpasta da categoria,
inclua-o no ``CONNECTORS`` da categoria e ele aparece automaticamente aqui.
"""

from stg.connectors.creds import CONNECTORS as CREDS
from stg.connectors.netmon import CONNECTORS as NETMON
from stg.connectors.recon import CONNECTORS as RECON
from stg.connectors.siem import CONNECTORS as SIEM
from stg.connectors.vuln import CONNECTORS as VULN
from stg.connectors.web import CONNECTORS as WEB

ALL_CONNECTORS = [*RECON, *VULN, *WEB, *CREDS, *NETMON, *SIEM]

__all__ = ["ALL_CONNECTORS"]
