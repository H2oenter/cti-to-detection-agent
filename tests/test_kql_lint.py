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


def test_parenthesised_arithmetic_is_not_a_table():
    """Regression: the reviewer caught this false positive on a real AA23-320A draft."""
    query = (
        "let regs = AuditLogs | where TimeGenerated > ago(7d)"
        " | project RegTime = TimeGenerated, Upn = tostring(InitiatedBy.user.userPrincipalName);\n"
        "regs | join kind=inner (SigninLogs | where TimeGenerated > ago(7d)"
        " | project Upn = UserPrincipalName, SigninTime = TimeGenerated) on Upn\n"
        "| where SigninTime between ((RegTime - 1h) .. (RegTime + 1h))"
    )
    assert codes(lint_kql(query, ["AuditLogs", "SigninLogs"], SCHEMA), "error") == []


def test_unknown_table_inside_a_join_is_caught():
    query = (
        "SigninLogs | where TimeGenerated > ago(1d)\n"
        "| join kind=inner (AuditLog | where TimeGenerated > ago(1d)) on CorrelationId"
    )
    assert "unknown_table" in codes(lint_kql(query, ["SigninLogs"], SCHEMA), "error")


def test_unknown_column_names_are_listed():
    query = 'DeviceProcessEvents | where Timestamp > ago(1d) | where ParentProcessName == "x"'
    [warning] = [f for f in lint_kql(query, ["DeviceProcessEvents"], SCHEMA)
                 if f.code == "unknown_columns"]  # fmt: skip
    assert "ParentProcessName" in warning.message


def test_strip_literals():
    assert strip_literals('a "x // y" b // tail\nc') == 'a "" b \nc'
    assert strip_literals("h'secret' @\"C:\\\" z") == '"" "" z'
    assert strip_literals("x = 'it\\'s'") == 'x = ""'
    assert strip_literals('x = @"say ""hi"" now" y') == 'x = "" y'  # doubled quotes inside


NODE_LINE = r'| where ProcessCommandLine matches regex @"(?i)\.(bat|cmd)\"?\s"'


def test_a_broken_verbatim_string_is_an_error():
    """Regression: the second reviewer caught this in a real CVE-2024-27980 draft. In @"..."
    the backslash doesn't escape the quote, so the string ends at \\" and ?\\s" is left over."""
    query = f"DeviceProcessEvents\n| where Timestamp > ago(1d)\n{NODE_LINE}\n| take 10"
    findings = {f.code: f.message for f in lint_kql(query, ["DeviceProcessEvents"], SCHEMA)
                if f.severity == "error"}  # fmt: skip
    assert set(findings) == {"broken_string", "unterminated_string"}
    assert r'(bat|cmd)\"?\s"' in findings["broken_string"]
    assert "write a quote inside it as" in findings["broken_string"]


@pytest.mark.parametrize(
    ("snippet", "code"),
    [
        ('"abc"def', "broken_string"),
        ("'one\ntwo'", "unterminated_string"),
        ('@"no end', "unterminated_string"),
        ("```never closed", "unterminated_string"),
    ],
)
def test_strings_kql_could_not_parse(snippet, code):
    query = f"DeviceProcessEvents | where Timestamp > ago(1d) | where FileName == {snippet}"
    assert code in codes(lint_kql(query, ["DeviceProcessEvents"], SCHEMA), "error")


@pytest.mark.parametrize(
    "snippet",
    [
        r'@"C:\Windows\Temp\"',  # a verbatim string can end in a backslash
        '@"say ""hi"""',
        r'"a\"b"',
        "h'secret'",
        "```one\ntwo```",
    ],
)
def test_strings_kql_reads_fine_stay_clean(snippet):
    query = f"DeviceProcessEvents | where Timestamp > ago(1d) | where FileName == {snippet}"
    assert codes(lint_kql(query, ["DeviceProcessEvents"], SCHEMA), "error") == []


def test_an_obfuscated_verbatim_string_cannot_hide_code():
    """h@"..." is verbatim too. Read with backslash escapes, the string below would seem to
    run on to the quote in the trailing comment and hide the externaldata call."""
    query = (
        "DeviceProcessEvents | where Timestamp > ago(1d)\n"
        '| where FolderPath has h@"C:\\x\\" | join (externaldata(u:string) '
        "[@'https://hunt.canary.example/x']) on $left.FolderPath == $right.u //\""
    )
    assert "external_data" in codes(lint_kql(query, ["DeviceProcessEvents"], SCHEMA), "error")


def test_schema_has_the_tables_hunts_need():
    for table in ("DeviceProcessEvents", "DeviceTvmSoftwareInventory", "SigninLogs", "W3CIISLog"):
        assert table in SCHEMA.tables
    assert "InitiatingProcessParentFileName" in SCHEMA.tables["DeviceProcessEvents"]
