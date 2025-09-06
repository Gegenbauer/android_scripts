# Python Google Style Guide for This Project

All Python code in this project must strictly follow the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html):

- Function and class definitions must be grouped at the top of the file, after imports and module-level docstring, before any executable code.
- Imports are always at the top of the file, in the order: standard library, third-party, local imports.
- Use snake_case for function and variable names, CapWords for class names.
- Use 4 spaces for indentation.
- Each function and class must have a docstring.
- No executable code (other than function/class definitions) should appear before all function/class definitions.
- Limit lines to 80 characters when possible.
- Use explicit relative imports for intra-package imports.
- Place module-level constants after imports and before function/class definitions.
- Do not insert functions or classes in the middle of other function/class definitions or after executable code.

**Prompt Enforcement:**
Copilot and all code generation tools must strictly follow this style guide for all Python code in this repository.

