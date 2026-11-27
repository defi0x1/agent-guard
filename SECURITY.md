# Security policy

Agent Guard is a security boundary. A tool call that should be red but passes green, a way for an
agent to change or pause the guard, or a secret that reaches a log or a hook answer is a
vulnerability.

## Reporting

Please report privately: the **Security** tab of this repository, then **Report a vulnerability**.
Do not open a public issue. Include the hook input (or the command) that gets through, what you
expected, and the version (`guard --version`).

You should hear back within a week.

## Known limits

The limits listed in the [README](README.md#limits) are known. They are not vulnerabilities, but
ideas for closing them are welcome as issues.
