"""add_tiered_access_tables

Creates the tables backing the tiered access control feature:
  - ai_models
  - applications
  - application_features
  - role_permissions
  - machine_installed_apps

Seeds:
  - Production Groq models at the appropriate min_tier (retires deepseek).
  - Common enterprise desktop apps (Excel, Word, PowerPoint, Outlook) with
    detect hints and protocol-handler launch URIs.
  - Default role_permissions for the five real roles.

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-04-21 00:10:00.000000

"""
import json
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = 'd2e3f4a5b6c7'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


TIER_NONE = 'none'
TIER_KEY_UNBOUND = 'key_unbound'
TIER_KEY_BOUND = 'key_bound'


def upgrade():
    op.create_table(
        'ai_models',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('slug', sa.String(128), nullable=False, unique=True),
        sa.Column('display_name', sa.String(128), nullable=False),
        sa.Column('min_tier', sa.String(32), nullable=False, server_default=TIER_KEY_BOUND),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        'application_catalog',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('slug', sa.String(128), nullable=False, unique=True),
        sa.Column('display_name', sa.String(128), nullable=False),
        sa.Column('detect_hints', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('min_tier', sa.String(32), nullable=False, server_default=TIER_KEY_BOUND),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        'application_features',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column(
            'application_id',
            sa.Integer,
            sa.ForeignKey('applications.id'),
            nullable=False,
        ),
        sa.Column('slug', sa.String(160), nullable=False, unique=True),
        sa.Column('display_name', sa.String(160), nullable=False),
        sa.Column('min_tier', sa.String(32), nullable=False, server_default=TIER_KEY_BOUND),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default=sa.true()),
    )

    op.create_table(
        'role_permissions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('role', sa.String(32), nullable=False),
        sa.Column('resource_type', sa.String(32), nullable=False),
        sa.Column('resource_id', sa.String(160), nullable=False),
        sa.Column('allowed', sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            'role', 'resource_type', 'resource_id', name='uq_role_resource'
        ),
    )

    op.create_table(
        'machine_installed_apps',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column(
            'machine_binding_id',
            sa.Integer,
            sa.ForeignKey('machine_bindings.id'),
            nullable=False,
        ),
        sa.Column(
            'application_id',
            sa.Integer,
            sa.ForeignKey('applications.id'),
            nullable=False,
        ),
        sa.Column('version', sa.String(64), nullable=True),
        sa.Column(
            'detected_at',
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            'machine_binding_id', 'application_id', name='uq_binding_app'
        ),
    )

    _seed(op.get_bind())


def _seed(bind):
    now = datetime.now(timezone.utc)

    # --- AI models (Groq production; deepseek retired) ---
    models = [
        # slug, display_name, min_tier, is_active
        ('openai/gpt-oss-20b', 'GPT-OSS 20B (fastest)', TIER_NONE, True),
        ('llama-3.1-8b-instant', 'Llama 3.1 8B Instant', TIER_KEY_UNBOUND, True),
        ('llama-3.3-70b-versatile', 'Llama 3.3 70B Versatile', TIER_KEY_BOUND, True),
        ('openai/gpt-oss-120b', 'GPT-OSS 120B', TIER_KEY_BOUND, True),
        # Preview — inactive until admin opts in.
        ('meta-llama/llama-4-scout-17b', 'Llama 4 Scout 17B (preview)', TIER_KEY_BOUND, False),
        ('qwen/qwen3-32b', 'Qwen3 32B (preview)', TIER_KEY_BOUND, False),
    ]
    for slug, name, tier, active in models:
        bind.execute(
            sa.text(
                "INSERT INTO ai_models (slug, display_name, min_tier, is_active, created_at)"
                " VALUES (:slug, :name, :tier, :active, :now)"
            ),
            {"slug": slug, "name": name, "tier": tier, "active": active, "now": now},
        )

    # --- Applications + features ---
    # detect_hints are used by the fingerprint helper to scan the host and by
    # the frontend to launch via OS protocol handlers.
    apps = [
        (
            'excel',
            'Microsoft Excel',
            {
                'windows_registry': 'Excel.exe',
                'macos_bundle_id': 'com.microsoft.Excel',
                'launch_uri': 'ms-excel:',
            },
            TIER_KEY_BOUND,
            [
                ('excel.basic', 'Open / edit workbooks', TIER_KEY_UNBOUND),
                ('excel.macros', 'Run macros / VBA', TIER_KEY_BOUND),
                ('excel.mail_merge_source', 'Use as mail-merge data source', TIER_KEY_BOUND),
            ],
        ),
        (
            'word',
            'Microsoft Word',
            {
                'windows_registry': 'Winword.exe',
                'macos_bundle_id': 'com.microsoft.Word',
                'launch_uri': 'ms-word:',
            },
            TIER_KEY_BOUND,
            [
                ('word.basic', 'Open / edit documents', TIER_KEY_UNBOUND),
                ('word.mail_merge', 'Mail merge', TIER_KEY_BOUND),
                ('word.macros', 'Run macros / VBA', TIER_KEY_BOUND),
            ],
        ),
        (
            'powerpoint',
            'Microsoft PowerPoint',
            {
                'windows_registry': 'POWERPNT.EXE',
                'macos_bundle_id': 'com.microsoft.Powerpoint',
                'launch_uri': 'ms-powerpoint:',
            },
            TIER_KEY_BOUND,
            [
                ('powerpoint.basic', 'Open / edit presentations', TIER_KEY_UNBOUND),
                ('powerpoint.macros', 'Run macros', TIER_KEY_BOUND),
            ],
        ),
        (
            'outlook',
            'Microsoft Outlook',
            {
                'windows_registry': 'OUTLOOK.EXE',
                'macos_bundle_id': 'com.microsoft.Outlook',
                'launch_uri': 'ms-outlook:',
            },
            TIER_KEY_UNBOUND,
            [
                ('outlook.basic', 'Read / send mail', TIER_KEY_UNBOUND),
                ('outlook.shared_mailboxes', 'Access shared mailboxes', TIER_KEY_BOUND),
            ],
        ),
    ]

    for slug, name, hints, tier, features in apps:
        result = bind.execute(
            sa.text(
                "INSERT INTO applications (slug, display_name, detect_hints, min_tier, is_active, created_at)"
                " VALUES (:slug, :name, CAST(:hints AS JSON), :tier, TRUE, :now)"
                " RETURNING id"
            ),
            {
                "slug": slug,
                "name": name,
                "hints": json.dumps(hints),
                "tier": tier,
                "now": now,
            },
        )
        app_id = result.scalar()

        for feat_slug, feat_name, feat_tier in features:
            bind.execute(
                sa.text(
                    "INSERT INTO application_features (application_id, slug, display_name, min_tier, is_active)"
                    " VALUES (:app_id, :slug, :name, :tier, TRUE)"
                ),
                {"app_id": app_id, "slug": feat_slug, "name": feat_name, "tier": feat_tier},
            )

    # --- Role permissions (seed defaults per the approved plan) ---
    # admin: everything. Others: tuned to enterprise expectations.
    ADMIN_SECTIONS = ('user_mgmt', 'audit_logs', 'key_mgmt', 'lockdown')

    all_model_slugs = [m[0] for m in models]
    all_app_slugs = [a[0] for a in apps]
    all_feature_slugs = [
        f[0] for a in apps for f in a[4]
    ]

    defaults = {
        'admin': {
            'model': set(all_model_slugs),
            'app': set(all_app_slugs),
            'app_feature': set(all_feature_slugs),
            'admin_section': set(ADMIN_SECTIONS),
        },
        'it': {
            'model': set(all_model_slugs),
            'app': set(all_app_slugs),
            'app_feature': set(all_feature_slugs),
            'admin_section': set(),
        },
        'manager': {
            'model': {
                'openai/gpt-oss-20b',
                'llama-3.1-8b-instant',
                'llama-3.3-70b-versatile',
                'openai/gpt-oss-120b',
            },
            'app': {'excel', 'word', 'powerpoint', 'outlook'},
            'app_feature': {
                'excel.basic', 'excel.macros', 'excel.mail_merge_source',
                'word.basic', 'word.mail_merge', 'word.macros',
                'powerpoint.basic', 'powerpoint.macros',
                'outlook.basic', 'outlook.shared_mailboxes',
            },
            'admin_section': set(),
        },
        'hr': {
            'model': {
                'openai/gpt-oss-20b',
                'llama-3.1-8b-instant',
                'openai/gpt-oss-120b',
            },
            'app': {'excel', 'word', 'outlook', 'powerpoint'},
            'app_feature': {
                'excel.basic', 'excel.mail_merge_source',
                'word.basic', 'word.mail_merge',
                'powerpoint.basic',
                'outlook.basic', 'outlook.shared_mailboxes',
            },
            'admin_section': set(),
        },
        'customer_service': {
            'model': {'openai/gpt-oss-20b', 'llama-3.1-8b-instant'},
            'app': {'outlook', 'word', 'excel'},
            'app_feature': {
                'outlook.basic',
                'word.basic',
                'excel.basic',
            },
            'admin_section': set(),
        },
    }

    for role, buckets in defaults.items():
        for resource_type, slugs in buckets.items():
            for slug in slugs:
                bind.execute(
                    sa.text(
                        "INSERT INTO role_permissions "
                        "(role, resource_type, resource_id, allowed, updated_at) "
                        "VALUES (:role, :rtype, :rid, TRUE, :now)"
                    ),
                    {
                        "role": role,
                        "rtype": resource_type,
                        "rid": slug,
                        "now": now,
                    },
                )


def downgrade():
    op.drop_table('machine_installed_apps')
    op.drop_table('role_permissions')
    op.drop_table('application_features')
    op.drop_table('application_catalog')
    op.drop_table('ai_models')
