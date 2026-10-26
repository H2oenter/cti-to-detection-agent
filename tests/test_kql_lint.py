import pytest
from conftest import ROOT

from cti_agent.util.kql_lint import KqlSchema, lint_kql, strip_literals

SCHEMA = KqlSchema.load(ROOT / "data" / "kql_schema.json")


def codes(findings, severity=None):
    return sorted(f.code for f in findings if severity in (None, f.severity))


PHP_CGI = """DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "php-cgi.exe"
| where FileName in~ ("cmd.exe", "powershell.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine"""

MFA_JOIN = """let window = 1d;
SigninLogs
| where TimeGenerated > ago(window)
| where ResultType == "500121"
| summarize Prompts = count() by UserPrincipalName, bin(TimeGenerated, 10m)
| where Prompts > 10
| join kind=inner (AuditLogs | where TimeGenerated > ago(window) | project Target = tostring(InitiatedBy), OperationName) on $left.UserPrincipalName == $right.Target"""  # noqa: E501


@pytest.mark.parametrize(
    ("query", "tables"),
    [
        (PHP_CGI, ["DeviceProcessEvents"]),
        (MFA_JOIN, ["SigninLogs", "AuditLogs"]),
        ("union DeviceProcessEvents, DeviceFileEvents\n| where Timestamp > ago(1d)",
         ["DeviceProcessEvents", "DeviceFileEvents"]),
        ("DeviceNetworkEvents | where Timestamp > ago(1d)\n"
         "| where DeviceId in ((DeviceInfo | where OSPlatform == \"Windows\" | project DeviceId))",
         ["DeviceNetworkEvents", "DeviceInfo"]),
    ],
)  # fmt: skip
def test_clean_queries_pass(query, tables):
    assert lint_kql(query, tables, SCHEMA) == []


@pytest.mark.parametrize(
    ("query", "code"),
    [
        ('let bad = externaldata(x:string) [@"https://evil.example/x"] with(format="txt");\n'
         "DeviceProcessEvents | where Timestamp > ago(1d)", "external_data"),
        ('DeviceProcessEvents | where Timestamp > ago(1d)\n| evaluate http_request("https://x")',
         "http_request"),
        ('DeviceProcessEvents | where Timestamp > ago(1d)\n| evaluate python(typeof(*), "x")',
         "code_plugin"),
        (".drop table DeviceProcessEvents", "management_command"),
        ('workspace("other").SigninLogs | where TimeGenerated > ago(1d)', "cross_scope"),
        ('cluster("x").database("y").T | take 1', "cross_scope"),
        ("DeviceProcessEvent | where Timestamp > ago(1d)", "unknown_table"),
        ("   ", "empty_query"),
    ],
)  # fmt: skip
def test_errors(query, code):
    assert code in codes(lint_kql(query, ["DeviceProcessEvents"], SCHEMA), "error")


@pytest.mark.parametrize(
    "query",
    [
        # Forbidden words inside strings and comments are data, not operators.
        'DeviceProcessEvents | where Timestamp > ago(1d)\n'
        '| where ProcessCommandLine has "externaldata" or ProcessCommandLine has "http_request"',
        "// externaldata and .drop are mentioned here only\n"
        "DeviceProcessEvents | where Timestamp > ago(1d)",
        'DeviceProcessEvents | where Timestamp > ago(1d)\n'
        '| where FolderPath startswith @"C:\\Windows\\Temp\\" and FileName != "x"',
    ],
)  # fmt: skip
def test_literals_and_comments_do_not_trigger(query):
    assert codes(lint_kql(query, ["DeviceProcessEvents"], SCHEMA), "error") == []


@pytest.mark.parametrize(
    ("query", "declared", "code"),
    [
        ('DeviceProcessEvents | where Timestamp > ago(1d) | where ParentProcessName == "x"',
         ["DeviceProcessEvents"], "unknown_columns"),
        ('DeviceProcessEvents | where FileName == "x"', ["DeviceProcessEvents"], "no_time_filter"),
        ("DeviceProcessEvents | where Timestamp > ago(1d)", ["DeviceNetworkEvents"],
         "tables_mismatch"),
        ("imProcessCreate | where TimeGenerated > ago(1d)", [], "unverified_source"),
    ],
)  # fmt: skip
def test_warnings(query, declared, code):
    findings = lint_kql(query, declared, SCHEMA)
    assert code in codes(findings, "warning")
    assert codes(findings, "error") == []


def test_unknown_column_names_are_listed():
    query = 'DeviceProcessEvents | where Timestamp > ago(1d) | where ParentProcessName == "x"'
    [warning] = [f for f in lint_kql(query, ["DeviceProcessEvents"], SCHEMA)
                 if f.code == "unknown_columns"]  # fmt: skip
    assert "ParentProcessName" in warning.message


def test_strip_literals():
    assert strip_literals('a "x // y" b // tail\nc') == 'a "" b \nc'
    assert strip_literals("h'secret' @\"C:\\\" z") == '"" "" z'
    assert strip_literals("x = 'it\\'s'") == 'x = ""'


def test_schema_has_the_tables_hunts_need():
    for table in ("DeviceProcessEvents", "DeviceTvmSoftwareInventory", "SigninLogs", "W3CIISLog"):
        assert table in SCHEMA.tables
    assert "InitiatingProcessParentFileName" in SCHEMA.tables["DeviceProcessEvents"]
