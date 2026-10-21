"""Render the submission cover page (group name, project title, GitHub link, team members) to PDF.

    python docs/submission/make_cover_pdf.py                       # uses docs/submission/cover.json
    python docs/submission/make_cover_pdf.py --out VSV23-cover.pdf

Edit cover.json to change the group name, title, link or members, then re-run.
Rendering uses the installed Microsoft Edge in headless mode via Playwright.
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: A4; margin: 22mm 20mm; }}
  body {{ font-family: 'Times New Roman', Times, serif; color: #000; }}
  h1 {{ text-align: center; font-size: 30pt; font-weight: bold; margin: 0 0 10pt; }}
  h2 {{ text-align: center; font-size: 20pt; font-weight: bold; line-height: 1.35; margin: 0 0 30pt; }}
  .link {{ font-size: 15pt; margin: 0 0 30pt 6pt; }}
  .link a {{ color: #1a56db; text-decoration: underline; }}
  .members-title {{ font-size: 15pt; margin: 0 0 6pt; }}
  ol {{ font-size: 15pt; margin: 0; padding-left: 34pt; line-height: 1.75; }}
  li {{ padding-left: 14pt; }}
  .todo {{ color: #b91c1c; font-style: italic; }}
</style></head><body>
  <h1>Group Name: {group}</h1>
  <h2>Title of the Project: {title}</h2>
  <p class="link">GitHub Repository Link: <a href="{link}">{link}</a></p>
  <p class="members-title">Team Members:</p>
  {members}
</body></html>"""


def member_line(m: dict) -> str:
    name = html.escape(m.get("name", "").strip())
    uid = html.escape(str(m.get("uid", "")).strip())
    role = html.escape(m.get("role", "").strip())
    if not name:
        return '<li class="todo">[member name] UID: [UID]</li>'
    text = f"{name} UID: {uid}" if uid else name
    if role:
        text += f" ({role})"
    return f"<li>{text}</li>"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(HERE / "cover.json"))
    ap.add_argument("--out", default=str(HERE / "VSV23-ZeroTrustVault-Submission.pdf"))
    a = ap.parse_args(argv)
    d = json.loads(Path(a.data).read_text(encoding="utf-8"))
    members = d.get("members") or []
    if members:
        members_html = "<ol>" + "".join(member_line(m) for m in members) + "</ol>"
    else:
        members_html = '<p class="todo" style="font-size:15pt;margin-left:6pt">[Add team member names and UIDs]</p>'
    page = PAGE.format(group=html.escape(d["group"]), title=html.escape(d["title"]), link=html.escape(d["github"]), members=members_html)
    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True)
        pg = b.new_page()
        pg.set_content(page, wait_until="load")
        pg.pdf(path=a.out, format="A4", print_background=True, margin={"top": "22mm", "bottom": "22mm", "left": "20mm", "right": "20mm"})
        b.close()
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
