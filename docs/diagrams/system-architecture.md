
%%{init: {"theme": "neutral", "flowchart": {"curve": "linear"}}}%%
flowchart TB
    Users["Security analysts / Remediation teams / Governance approvers"]
    Sources["Generic CSV / Nessus CSV / Nuclei JSONL / PTRAC"]

    subgraph Application["Arbitrator — FastAPI Application"]
        direction TB

        subgraph Presentation["Presentation and Access Control"]
            Web["FastAPI Routes / Jinja2 Templates"]
            Auth["Authentication / RBAC / CSRF"]
            Web --> Auth
        end

        subgraph Domain["Application and Domain Services"]
            Import["Import Adapters"]
            Identity["Asset and Vulnerability Identity"]
            Correlation["Finding Tracking and Advisory Correlation"]
            Routing["Remediation Ownership and Routing"]
            Governance["Governance Decisions and Work Items"]
            Reporting["Registers and Dashboard"]

            Import --> Identity
            Identity --> Correlation
            Correlation --> Routing
            Routing --> Governance
        end

        subgraph Persistence["Persistence Layer"]
            ORM["SQLAlchemy / Transactions"]
        end

        Auth --> Import
        Auth --> Governance
        Auth --> Reporting

        Correlation --> ORM
        Routing --> ORM
        Governance --> ORM
        Reporting --> ORM
    end

    DB[("SQLite Database")]

    Users --> Web
    Sources -->|Authorized upload| Web
    ORM <-->|Read / Write| DB

    Tenable["Tenable"]
    ServiceNow["ServiceNow"]

    Tenable -.->|Optional import| Import
    Governance -.->|Optional incident linkage| ServiceNow

