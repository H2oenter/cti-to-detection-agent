"""Stage 6: the human gate. Nothing is approved, edited or published without a person.

Every decision is tied to the exact content it was made on (the item hash) and written
to the audit log. Approved items are rebuilt into out/<run>/approved/ after each
decision; publish later checks that what it sends still matches what was approved.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import stix2

from cti_agent.audit import AuditLog
from cti_agent.config import Settings
from cti_agent.models import Hunt
from cti_agent.outputs.kql_out import render_kql
from cti_agent.outputs.stix_out import TOOL_IDENTITY
from cti_agent.stages.reviewer import attention_reasons
from cti_agent.stages.store import SCHEMA
from cti_agent.util.kql_lint import KqlSchema, lint_kql
from cti_agent.util.normalise import item_hash

# Review order; relationships, reports, identities and markings follow from these.
STIX_KINDS = ("indicator", "threat-actor", "vulnerability", "attack-pattern")
ORDER = {"hunt": 0, **{kind: i + 1 for i, kind in enumerate(STIX_KINDS)}}
# Kinds where one decision may cover the rest of the same type. Never hunts or indicators:
# those are what reaches detections, so each gets its own look.
BULK_KINDS = {"threat-actor", "vulnerability", "attack-pattern"}
PROTECTED_STIX = ("id", "type", "spec_version", "created", "created_by_ref")
# Lint codes about the draft's evidence rather than its KQL; an edit keeps them.
EVIDENCE_CODES = {"no_evidence", "evidence_not_given", "technique_mismatch"}


class GateError(Exception):
    pass


@dataclass
class ReviewItem:
    ref: str  # draft:<draft_id> or stix:<stix_id>
    kind: str  # "hunt" or a STIX type
    hunt: Hunt | None = None
    stix: dict | None = None

    @property
    def hash(self) -> str:
        return self.hunt.item_hash if self.hunt else item_hash(self.stix)

    @property
    def label(self) -> str:
        if self.hunt:
            return f"{self.hunt.technique_id}: {self.hunt.draft.title}"
        name = self.stix.get("name") or self.stix["id"]
        ref = next(
            (r.get("external_id") for r in self.stix.get("external_references", [])
             if r.get("external_id")),
            None,
        )  # fmt: skip
        return f"{ref}: {name}" if ref and ref != name else name


class Gate:
    def __init__(self, settings: Settings, run_id: str, actor: str, audit: AuditLog) -> None:
        self.settings = settings
        self.run_id = run_id
        self.actor = actor
        self.audit = audit
        self.out_dir = settings.out_dir / run_id
        if not self.out_dir.exists():
            raise GateError(f"no run {run_id} in {settings.out_dir}")
        audit.verify()  # raises AuditChainBroken: never decide on top of a tampered log
        self.schema = KqlSchema.load(settings.kql_schema_file)
        self.items = self._load()

    # --- loading -------------------------------------------------------------------------

    def _connect(self):
        conn = sqlite3.connect(self.settings.db_path)
        conn.executescript(SCHEMA)
        return closing(conn)

    def _load(self) -> list[ReviewItem]:
        items: list[ReviewItem] = []
        with self._connect() as conn:
            for draft_id, raw in conn.execute(
                "SELECT draft_id, json FROM drafts WHERE run_id = ? ORDER BY rowid", (self.run_id,)
            ):
                items.append(
                    ReviewItem(f"draft:{draft_id}", "hunt", hunt=Hunt.model_validate_json(raw))
                )
            for stix_id, kind, raw in conn.execute(
                "SELECT stix_id, type, json FROM objects WHERE run_id = ? ORDER BY rowid",
                (self.run_id,),
            ):
                if kind in STIX_KINDS:
                    items.append(ReviewItem(f"stix:{stix_id}", kind, stix=json.loads(raw)))
        items.sort(key=lambda i: ORDER[i.kind])
        return items

    def item(self, ref: str) -> ReviewItem:
        found = next((i for i in self.items if i.ref == ref), None)
        if found is None:
            raise GateError(f"no item {ref} in run {self.run_id}")
        return found

    # --- status --------------------------------------------------------------------------

    def status(self, item: ReviewItem) -> str:
        """pending, approved, rejected, or changed (edited or regenerated since decided)."""
        latest = self.audit.latest_decisions(self.run_id).get(item.ref)
        if latest is None:
            return "pending"
        if latest["item_hash"] != item.hash:
            return "changed"
        return "approved" if latest["decision"] == "approve" else "rejected"

    def pending(self, include_decided: bool = False) -> list[ReviewItem]:
        return [
            i for i in self.items if include_decided or self.status(i) in ("pending", "changed")
        ]

    # --- decisions -----------------------------------------------------------------------

    def decide(
        self, item: ReviewItem, decision: str, reason: str | None = None, bulk: bool = False
    ) -> None:
        if decision not in ("approve", "reject"):
            raise GateError(f"unknown decision {decision!r}")
        if decision == "reject" and not (reason or "").strip():
            raise GateError("a rejection needs a reason")
        if decision == "approve" and item.hunt and item.hunt.lint_failed:
            errors = ", ".join(f.code for f in item.hunt.lint if f.severity == "error")
            raise GateError(f"{item.ref} has lint errors ({errors}); edit it before approving")
        if bulk and item.kind not in BULK_KINDS:
            raise GateError(f"{item.kind} items are reviewed one at a time")
        self.audit.append(
            run_id=self.run_id, actor=self.actor, action="review", item_ref=item.ref,
            item_hash=item.hash, decision=decision, reason=reason, bulk=bulk,
        )  # fmt: skip
        self._set_status(item, "approved" if decision == "approve" else "rejected")
        self.rebuild_approved()

    def decide_rest_of_type(self, item: ReviewItem, decision: str, reason: str | None) -> int:
        """Apply one decision to this item and every remaining pending item of its type."""
        if item.kind not in BULK_KINDS:
            raise GateError(f"{item.kind} items are reviewed one at a time")
        targets = [i for i in self.pending() if i.kind == item.kind]
        for target in targets:
            self.decide(target, decision, reason, bulk=True)
        return len(targets)

    def _set_status(self, item: ReviewItem, status: str) -> None:
        table, key = ("drafts", "draft_id") if item.hunt else ("objects", "stix_id")
        with self._connect() as conn, conn:
            conn.execute(
                f"UPDATE {table} SET review_status = ? WHERE run_id = ? AND {key} = ?",
                (status, self.run_id, item.ref.split(":", 1)[1]),
            )

    # --- edits ---------------------------------------------------------------------------

    def edit_hunt(self, item: ReviewItem, new_query: str) -> ReviewItem:
        if item.hunt is None:
            raise GateError(f"{item.ref} is not a hunt")
        hunt = item.hunt
        if new_query.strip() == hunt.draft.query.strip():
            return item
        draft = hunt.draft.model_copy(update={"query": new_query.strip()})
        lint = [f for f in hunt.lint if f.code in EVIDENCE_CODES] + lint_kql(
            draft.query, draft.tables, self.schema
        )
        reasons = attention_reasons(hunt.review, lint, hunt.review_outcome)
        if hunt.review:
            reasons.append(f"edited by {self.actor} after the model review")
        edited = hunt.model_copy(
            update={
                "draft": draft,
                "lint": lint,
                "item_hash": item_hash(draft),
                "needs_attention": bool(reasons),
                "attention_reasons": reasons,
            }
        )
        new = ReviewItem(item.ref, item.kind, hunt=edited)
        self._record_edit(item, new)
        with self._connect() as conn, conn:
            conn.execute(
                "UPDATE drafts SET json = ?, item_hash = ?, needs_attention = ?, "
                "review_status = 'pending' WHERE run_id = ? AND draft_id = ?",
                (edited.model_dump_json(), edited.item_hash, int(edited.needs_attention),
                 self.run_id, edited.draft_id),
            )  # fmt: skip
        return self._replace(new)

    def edit_stix(self, item: ReviewItem, new_json: str) -> ReviewItem:
        if item.stix is None:
            raise GateError(f"{item.ref} is not a STIX object")
        try:
            obj = json.loads(new_json)
        except json.JSONDecodeError as exc:
            raise GateError(f"not valid JSON: {exc}") from exc
        if obj == item.stix:
            return item
        old = item.stix
        changed = [k for k in PROTECTED_STIX if obj.get(k) != old.get(k)]
        changed += sorted(
            k for k in set(old) | set(obj)
            if k.startswith("x_cti_agent_") and k != "x_cti_agent_edited_by"
            and obj.get(k) != old.get(k)
        )  # fmt: skip
        if changed:
            raise GateError(f"these fields record provenance and can't be edited: {changed}")
        obj["modified"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        obj["x_cti_agent_edited_by"] = self.actor
        try:
            stix2.parse(json.dumps(obj), allow_custom=True)
        except Exception as exc:  # stix2 raises several exception types for invalid objects
            raise GateError(f"the edited object isn't valid STIX: {exc}") from exc
        new = ReviewItem(item.ref, item.kind, stix=obj)
        self._record_edit(item, new)
        with self._connect() as conn, conn:
            conn.execute(
                "UPDATE objects SET json = ?, review_status = 'pending' "
                "WHERE run_id = ? AND stix_id = ?",
                (json.dumps(obj), self.run_id, obj["id"]),
            )
        return self._replace(new)

    def _record_edit(self, old: ReviewItem, new: ReviewItem) -> None:
        self.audit.append(
            run_id=self.run_id, actor=self.actor, action="edit", item_ref=old.ref,
            item_hash=new.hash, detail={"previous_hash": old.hash},
        )  # fmt: skip

    def _replace(self, new: ReviewItem) -> ReviewItem:
        self.items = [new if i.ref == new.ref else i for i in self.items]
        self.rebuild_approved()
        return new

    # --- approved/ -----------------------------------------------------------------------

    def approved(self) -> list[ReviewItem]:
        return [i for i in self.items if self.status(i) == "approved"]

    def rebuild_approved(self) -> Path:
        """out/<run>/approved/ holds exactly what is approved now, and nothing else."""
        root = self.out_dir / "approved"
        hunts_dir = root / "hunts"
        hunts_dir.mkdir(parents=True, exist_ok=True)
        for old in hunts_dir.glob("*.kql"):
            old.unlink()
        latest = self.audit.latest_decisions(self.run_id)
        approved = self.approved()
        for item in approved:
            if item.hunt:
                decision = latest[item.ref]
                text = render_kql(item.hunt).replace(
                    "// DRAFT HUNT: not approved by a human. Do not deploy before review.",
                    f"// APPROVED by {decision['actor']} at {decision['ts']} (item {item.hash})",
                    1,
                )
                (hunts_dir / f"{item.hunt.draft_id}.kql").write_text(text, encoding="utf-8")

        objects = [i.stix for i in approved if i.stix]
        bundle_path = root / "stix-bundle.json"
        if objects:
            ids = {o["id"] for o in objects}
            run_objects = self._run_objects()
            relationships = [
                o for o in run_objects
                if o["type"] == "relationship" and o["source_ref"] in ids and o["target_ref"] in ids
            ]  # fmt: skip
            markings = self._markings(
                {ref for o in objects for ref in o.get("object_marking_refs", [])}
            )
            bundle = {
                "type": "bundle",
                "id": _bundle_id(self.run_id, ids),
                "objects": [*markings, json.loads(TOOL_IDENTITY.serialize()), *objects,
                            *relationships],
            }  # fmt: skip
            bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        elif bundle_path.exists():
            bundle_path.unlink()
        return root

    def _run_objects(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT json FROM objects WHERE run_id = ?", (self.run_id,))
            return [json.loads(raw) for (raw,) in rows]

    def _markings(self, refs: set[str]) -> list[dict]:
        bundle_file = self.out_dir / "bundle.json"
        if not refs or not bundle_file.exists():
            return []
        bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
        return [o for o in bundle["objects"] if o["id"] in refs]


def _bundle_id(run_id: str, ids: set[str]) -> str:
    return f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, run_id + '|' + '|'.join(sorted(ids)))}"
