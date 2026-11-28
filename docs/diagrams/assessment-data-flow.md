
%%{init: {"theme": "neutral", "flowchart": {"curve": "linear"}}}%%
flowchart TD
    A["Authorized assessment file"] --> B["Validate format and parse records"]

    B --> C{"Valid input?"}

    C -->|No| D["Report validation errors"]
    C -->|Yes| E["Normalize FindingInput records"]

    E --> F["Resolve global asset"]
    F --> G["Resolve source-scoped vulnerability"]

    G --> H{"Existing source-scoped finding?"}

    H -->|Yes| I["Reuse tracked finding"]
    H -->|No| J["Create tracked finding"]

    I --> K["Record assessment observation"]
    J --> K

    K --> L["Evaluate cross-source candidates"]

    L --> M{"Potential relationship?"}

    M -->|Yes| N["Present advisory candidate"]
    M -->|No| O["Retain independent finding"]

    N --> P["Preserve independent records"]
    O --> P

    P --> Q["Apply ownership routing"]

    Q --> R{"Remediation team assigned?"}
    R -->|Yes| S["Remediation workflow"]
    R -->|No| T["Unassigned triage"]

    S --> U["Governance and reporting"]
    T --> U

