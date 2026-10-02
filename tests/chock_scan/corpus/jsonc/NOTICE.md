# Vendored JSONC corpus

Real configuration files, copied byte for byte, that `chock_scan/jsonc.py` must read without error.
Test data only: nothing here is shipped or executed.

| file | source | licence |
|---|---|---|
| `vscode.settings.json` | microsoft/vscode@3d4ac27bf3d47c15590d4ef34f8f737f155d0b96 `.vscode/settings.json` | MIT (A) |
| `vscode.launch.json` | microsoft/vscode@3d4ac27bf3d47c15590d4ef34f8f737f155d0b96 `.vscode/launch.json` | MIT (A) |
| `vscode.tasks.json` | microsoft/vscode@3d4ac27bf3d47c15590d4ef34f8f737f155d0b96 `.vscode/tasks.json` | MIT (A) |
| `vscode.extensions.json` | microsoft/vscode@3d4ac27bf3d47c15590d4ef34f8f737f155d0b96 `.vscode/extensions.json` | MIT (A) |
| `vscode.devcontainer.json` | microsoft/vscode@3d4ac27bf3d47c15590d4ef34f8f737f155d0b96 `.devcontainer/devcontainer.json` | MIT (A) |
| `vscode.tsconfig.base.json` | microsoft/vscode@3d4ac27bf3d47c15590d4ef34f8f737f155d0b96 `src/tsconfig.base.json` | MIT (A) |
| `vscode-1.80.0.eslintrc.json` | microsoft/vscode@660393deaaa6d1996740ff4880f1bad43768c814 (tag 1.80.0) `.eslintrc.json` | MIT (A) |
| `copilot-chat.vscode-mcp.json` | microsoft/vscode-copilot-chat@5863f5a7088958050792b5dccbe8b46c6e13eccc `.vscode/mcp.json` | MIT (B) |
| `copilot-chat.devcontainer.json` | microsoft/vscode-copilot-chat@5863f5a7088958050792b5dccbe8b46c6e13eccc `.devcontainer/devcontainer.json` | MIT (B) |
| `templates-python.devcontainer.json` | devcontainers/templates@374497ae00fd50fd235812fe5d65e3be586690fa `src/python/.devcontainer/devcontainer.json` | MIT (C) |
| `mastra.cursor-mcp.json` | mastra-ai/mastra@0029fab656135dd56cd1adc89e6d81f769460e3e `.cursor/mcp.json` | Apache-2.0 (D) |

Claude Code settings are covered by this repository's own `.claude/settings.json`, read in place
(Claude Code's published examples are not under an open licence).

Copyright notices:

- (A) Copyright (c) 2015 - present Microsoft Corporation
- (B) Copyright (c) Microsoft Corporation. All rights reserved.
- (C) Copyright (c) 2022 Microsoft Corporation. All rights reserved.
- (D) Copyright (c) 2025 Kepler Software, Inc. Licensed under the Apache License 2.0, the licence of
  this repository (`LICENSE` at its root).

MIT License text, for (A), (B) and (C):

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
