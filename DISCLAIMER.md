# DISCLAIMER & TERMS OF USE

**AVA (Authorized Vulnerability Assessor) is a tool for AUTHORIZED security
testing only.**

## You may use this tool ONLY when ALL of the following are true:

1. You own the target system, **or** you have **explicit, written
   authorization** from the system's owner to perform security testing
   against it.
2. The testing falls within the **scope** that the owner authorized
   (hosts, paths, time windows, and intensity).
3. You comply with all applicable laws and regulations in your jurisdiction
   and the target's jurisdiction.

## What this tool will NOT do

- It will not run without an explicit `--i-have-authorization` assertion and
  a `scope.yaml` file declaring the in-scope hosts/paths.
- It will not send requests to hosts outside the declared scope, and it will
  not follow redirects that leave the declared scope.
- It will not send **destructive** payloads. By design it excludes payloads
  intended to delete or corrupt data (e.g. `DROP TABLE`, `; rm -rf`) or to
  exhaust resources / deny service. Its active checks aim to **confirm that a
  vulnerability is exploitable**, not to exploit it for damage.

## Legal notice

Unauthorized access to computer systems is a crime in most jurisdictions
(e.g. the U.S. Computer Fraud and Abuse Act, the U.K. Computer Misuse Act,
and equivalents worldwide). Running this tool against systems you are not
authorized to test may expose you to **criminal and civil liability**.

The authors and contributors of AVA accept **no liability** for misuse of
this software or for any damage arising from its use. By using AVA you accept
sole responsibility for ensuring you have proper authorization.

**If you are not certain you are authorized, do not run this tool.**
