# Architecture diagram: current-v2 trust path

```mermaid
flowchart TB
  SOURCE["Untrusted original repository"] --> CAPTURE["Source identity + stable disposable copy"]
  CONFIG["Normalized configuration"] --> PLAN["Typed baseline/candidate plan"]
  CAPTURE --> PLAN
  PLAN --> ADAPTER["Selected ecosystem adapter"]
  ADAPTER --> RESOLVE["Resolve immutable image digest"]
  RESOLVE --> FETCH["FETCH: declared network"]
  FETCH --> TEST["TEST: network none"]
  TEST --> ATTEMPTS["Typed raw attempts + logs"]
  ATTEMPTS --> CLASSIFY["Derived verdicts + frontier"]
  CAPTURE --> IDENTITY["Source/config/manifest/tool/adapter identity"]
  RESOLVE --> IDENTITY
  ENGINE["Container engine name + version"] --> IDENTITY
  CLASSIFY --> FINALIZE["Exact recursive v2 inventory finalizer"]
  IDENTITY --> FINALIZE
  FINALIZE --> VERIFY["No-follow verifier: checksums + semantic closure"]
  VERIFY -->|"PASS"| READGATE["Operation lock + stable trusted read"]
  VERIFY -->|"FAIL"| REJECT["BLOCKED / no trusted decision"]
  READGATE --> REPORT["Transactional report"]
  READGATE --> COMPARE["Verified base/head compare"]
  READGATE --> REPLAY["Fresh-copy, append-only transactional replay"]
  REPLAY --> RESOLVE
  REPLAY --> FINALIZE
```

## Evidence binding

```mermaid
flowchart LR
  RUNSUM["run checksums v2"] --> RUNFILES["Exact run-level files"]
  RUNSUM --> SCSUM["scenarios/&lt;id&gt;/checksums.txt"]
  SCSUM --> SCFILES["Scenario metadata, commands, phases, raw attempts, verdict mirror"]
  SCSUM --> REPLAYS["replays/attempt-N complete records"]
  RUNFILES --> WORKMAN["workspace-manifest.json"]
  WORKMAN --> WORKSPACE["Exact captured source-file inventory"]
```

The checksum graph detects changes and omissions; it is not a cryptographic signature or external attestation.

## Trust boundaries

```mermaid
flowchart TB
  subgraph HOST["Trusted local computing base"]
    TC["TomorrowCI CLI/core/verifier"]
    FS["Host OS + filesystem"]
    CE["Docker/Podman engine"]
  end
  subgraph UNTRUSTED["Untrusted execution inputs"]
    REPO["Target source"]
    IMAGE["Registry image + packages"]
    LOGS["Logs and failure text"]
  end
  subgraph EXTERNAL["Not established by Phase 1"]
    SIGNER["Independent signer / provenance trust root"]
    QUAL["External qualification + release authority"]
  end
  TC --> CE
  FS --> TC
  REPO --> CE
  IMAGE --> CE
  CE --> LOGS
  SIGNER -.-> TC
  QUAL -.-> TC
```

Container isolation, registry provenance, and external trust remain residual dependencies. M2 through M5 are not qualified by the current-v2 evidence path.
