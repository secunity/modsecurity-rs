Convert this C++ codebase to Rust while preserving its existing architecture and organization.

The codebase is already well organized. Treat its folder structure, component boundaries, object responsibilities, and separation of concerns as intentional design decisions.

### Preserve the design

- Keep the existing directory hierarchy and component names wherever practical, adapting filenames to Rust conventions.
- Map C++ namespaces to Rust modules and classes to structs/enums with associated implementations, preserving their responsibilities.
- Keep related functionality in the corresponding files and modules. Do not flatten the project, merge unrelated components, or introduce a new architecture.
- Preserve public behavior, algorithms, configuration semantics, file formats, and protocol compatibility.
- Preserve useful comments and documentation, updating references to match the Rust implementation.
- Avoid unrelated cleanup, new features, and speculative abstractions.

### Use idiomatic Rust within that structure

- Translate the design and behavior rather than mechanically translating C++ syntax.
- Use ownership, borrowing, enums, traits, and `Result` where appropriate.
- Preserve interfaces conceptually; adapt signatures where Rust requires a different expression of ownership or errors.
- Use traits for meaningful abstraction or polymorphism, rather than creating a trait for every class.
- Choose ownership based on actual lifetimes and responsibilities. Do not use excessive cloning, `Rc`, `Arc`, or interior mutability merely to bypass borrow-checker difficulties.
- Prefer safe Rust. Introduce `unsafe` only when necessary, documenting the safety invariants.
- Select dependencies conservatively and explain significant additions.
- Preserve binary layouts and ABI requirements explicitly wherever they are part of an external interface.

### Migration workflow

1. Inspect the codebase, build system, dependencies, tests, and entry points.
2. Summarize the architecture and provide a concise mapping from the existing directories and major types to their Rust equivalents.
3. Identify places where C++ features require a different Rust representation, such as inheritance, shared ownership, templates, or pointer-based relationships.
4. Implement the migration incrementally in coherent components, keeping the Rust project buildable at meaningful checkpoints.
5. Port existing tests and add targeted tests for behavior that could change during translation. Where practical, compare the C++ and Rust implementations using the same inputs.
6. Run formatting, compilation, relevant tests, and Clippy. Investigate failures rather than suppressing them without justification.

Keep the original C++ source available for reference and comparison until the migration is validated. Follow an existing migration layout if one exists; otherwise, place the Rust project in a separate directory that mirrors the original component hierarchy.

Do not stop after producing a plan: proceed with implementation. Make routine decisions independently. If preserving the existing organization becomes impractical, make the smallest necessary adjustment and explain why. Ask for clarification only when a decision materially affects externally visible behavior or requires a substantial architectural change.

At completion, report what was migrated, any structural deviations, verification results, and remaining gaps. Do not claim completion if functionality is missing, stubbed, or untested.