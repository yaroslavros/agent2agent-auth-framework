---
title: "Agent-to-Agent Authentication and Authorization"
abbrev: "A2A-Auth"
category: info

docname: draft-agent2agent-kasselman_lombardo-agent2agent-auth-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "PieterKas/agent2agent-auth-framework"
  latest: "https://PieterKas.github.io/agent2agent-auth-framework/draft-agent2agent-kasselman_lombardo-agent2agent-auth.html"

author:
 -
    fullname: "PieterKas"
    organization: Your Organization Here
    email: "pieter@defakto.security"

 -
    fullname: Jean-François Lombardo
    nickname: Jeff
    organization: AWS
    country: Canada
    email: jeffsec@amazon.com
normative:

informative:

...

--- abstract

This document proposes a framework for secure agent-to-agent (A2A) interactions leveraging existing standards such as OAuth 2.0 and the Workload Identity Management and Secure Exchange (WIMSE) architecture. Rather than defining new protocols, this document explores how existing and widely deployed stnadards can be applied or extended to establish agent-to-agent authentication and authorization. By doing so, it aims to provide a framewrok within which to identify protocol gaps, align terminology, and guide future standardization efforts for secure A2A communication.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Agent as a workload
Key point - for purposes of this document, Agent is a workload that calls an LLM (or similar) and tools in a loop until a terminating condition is met as determined by the LLM or agent. Create a diagram.

# Agent Attestation
Key point - agent attestation is the equivalent of identiy proofing. there are numerous mechanisms through which this may be achieved, which are deployment and risk specific. Reference WIMSE and SPIFFE approaches here.

# Agent Identifier
Key point - agents must be uniquely identified. Proposal is to use a WIMSE or WIMSE compatible identifier (basicaly a URI). Refer to WIMSE identifier draft.

# Agent Credentials
Key point - identifier must be bound to a credential. Credentials have expiry dates and additional attributes relevant to the agent. multiple formats are possible. JWTs, X.509 and WITs. Reference SPIFFE, WIMSE. Refer to API keys as an anit pattern.

# Agent Credential Provisioning
Key point - credentials are dynamically provisioned at runtime, they are short lived to remove need for expiry management. Provisioning includes initial provisioning and rotation. Refer to SPIFFE and WIMSE.

# Agent Authentication
Key point - agents may authenticate in a number of ways based on credentials, supported protocols and environment. Distinguish between network and application layer. Refernece WIMSE.

## Network layer authentication
MTLS

## Application layer authentication
WPT, HTTP Sig.

# Agent Authorization
Key point - OAuth is broadly supported and provides a delegation model for users to clients (aka agents). Agents can obtain acess tokens directly (client credentials flow, using above authentication methods) or it can be delegated to them by a user (OAuth flows). Make point that the access token includes the client_id, which is the same as the Agent ID (ore related to it) and can be used for authroization decisions, along with other claims in an Access Token (reference JWT Access token spec). Make provision for opaque tokens as well. Discuss Downscoping of agent authorization using transaction tokens. Discuss cross-domain authorization (use cases) and how it may be achieved (identity chaining and cross-domain authorization). Discuss human in the loop authroization. Note concerns, refer to cross-device BCP as examples of consent phishing attacsk. Talk about CIBA as a protocol.

## Same Domain Authorization

### Agent-to-Tool Authorization

### Agent-to-Agent Authorization

### User Delegated Authroization

### Downscoping Agent Authorization

### Human-in-the loop

## Cross Domain Agent-to-Agent Authroization

# Agent Monitoring and Remediation
Key point - ongoing monitoring and remediation is needed. Use protocols like SSE, CAEP to respond to changes in authorization. Note the need for ongoing logging and audit trails. Talk about end-to-end audit and how this is enabled by having agent identifiers.

# Agent Identity Policy
Key point - configuration and parameters for all the above constitutes policy. Not stnadardises and not recommended for standrdisation? Perhaps somethign about document format?

# Agent Compliance
Key point - audit against Agent Identity Policy - not standrdised and not recommended to standardise.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
