"""Geracao de relatorios consolidados (JSON, Markdown, HTML)."""

from stg.reporting.reporter import build_context, generate_report, render_report

__all__ = ["build_context", "generate_report", "render_report"]
