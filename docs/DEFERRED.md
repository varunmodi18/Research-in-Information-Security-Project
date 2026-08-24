# DEFERRED

Considered and postponed, per `PLAN.md` §14. None of the items below may be built in this stage.

| Item | Why deferred |
|---|---|
| BAN assumption ablation | New analysis; RP9 performs a derivation, not a sensitivity study |
| Wall-clock benchmarking of our implementation | Measures pure-Python reference code on a modern CPU; not comparable to RP9's sensor-node figures |
| Measured counterparts of Figs. 10-11 | Same reason |
| Any energy, battery or exhaustion model for §4.2 | RP9 states the claim qualitatively and supplies no model |
| Comparative operation counting between ICMDS and MAKA under DoS | New measurement RP9 does not perform |
| Any resolution of AM-05 | Would be a new protocol |
| Any repair of OB-01 or OB-02 | New design work |
| Substituting the OB-04 argument for RP9's §6.1.3 reasoning | Would silently overwrite the authors' claim; both are demonstrated instead |
| Adjudicating ER-05 | ICMDS-P is internally inconsistent about who selects `s`; determining true intent would be original cryptanalysis |
| Implementing ICMDS-P's Steps 1-8 in full | RP9 explicitly excludes CH selection and recovery from its review |
| Post-quantum primitives, revocation, forward secrecy | Subject of the next stage |
