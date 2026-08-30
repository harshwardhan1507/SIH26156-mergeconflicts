# Investigation Rules

These rules govern the structured reverse-engineering and architecture analysis of the Universal Log Pre-processing Framework (ULPF) repository:

1. **Evidence before conclusions.** Every finding, capability assertion, and structural mapping must be supported by verifiable code references, file paths, line numbers, or test executions.
2. **Never invent behavior.** Do not assume or extrapolate functionality that is not explicitly present in the source code or test suites.
3. **Clearly label UNKNOWN information.** If a component, integration point, or behavior cannot be determined from repository evidence, explicitly designate it as `UNKNOWN`.
4. **Distinguish observed facts from inference.** Factual observations (e.g. "function X calls function Y") must be clearly separated from architectural interpretations.
5. **Reference exact files and symbols whenever possible.** Use precise file paths, class names, function signatures, and schema properties in all documentation.
6. **Do not propose improvements during investigation.** Phase 0 and investigation phases are strictly analytical and descriptive; optimization and refactoring proposals are prohibited.
7. **Do not modify application code.** The core codebase, parsers, pipelines, and tests must remain unmodified throughout the investigation.
8. **Do not treat README claims as proof.** Claims in documentation, comments, or marketing materials must be independently verified against concrete code implementations.
