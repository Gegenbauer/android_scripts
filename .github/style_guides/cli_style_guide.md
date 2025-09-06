# Command-Line Interface (CLI) Style Guide

This document outlines the best practices for designing command-line interfaces (CLIs) for scripts within this project.

## Guiding Principles

The primary goal is to create CLIs that are both efficient for frequent users and clear for new users or for those reading scripts.

## Argument Style

- **Long Options**: Use `kebab-case` for all long options (e.g., `--device-path`, `--convert-mat`). They are descriptive and easy to read.

- **Short Options**:
  - **Provide** a short, single-letter option (e.g., `-p`) only for **high-frequency, core, or required parameters**. This significantly improves efficiency for interactive use.
  - **Avoid** providing short options for boolean flags, functional modifiers, or less common optional parameters. For these, a descriptive long option is better for clarity and self-documentation.
    - **Good Example**: `--no-open`, `--force`, `--ignore-cache`.
    - **Bad Example**: `-n` for `--no-open` (ambiguous).

- **Help Text**: Always provide clear and concise help text for every argument using the `help="..."` parameter in `add_argument`.

## Example

```python
# Good practice
parser.add_argument(
    "-p", "--package",
    required=True,
    help="The package name of the target application."
)
parser.add_argument(
    "--convert-mat",
    action="store_true", # A boolean flag
    help="Convert the hprof file to MAT format after pulling."
)

# Bad practice
parser.add_argument(
    "-c", "--convert-mat", # Unnecessary short option for a modifier
    action="store_true",
    help="Convert the hprof file to MAT format after pulling."
)
```
