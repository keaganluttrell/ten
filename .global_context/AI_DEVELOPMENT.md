# AI Development

## The Node

The Node is the single building block of the tree. A Node has a parent (unless root), and zero or more children. 

The Root Node is the top level of our project.

In this context of the AI tree, a Node is a module of code that should have its own isolated context from the entire repository.  Like in a tree, an Node has a data structure.

Ours is like this:

```text
Node
  global_context - This is the global context of the project
  inherited_context - This is the specific context from the parent as to why this node exists
  local_context - This is the specific context of the node
    INTENT (Markdown)
      This is the purpose of the node
    SPECIFICATION (Markdown)
      Inputs
      Outputs
      Dependencies
      Constraints
      Inner Module Detection (This will determine the child nodes)
    DESIGN (Markdown)
      This is the Diagrams, Pseudocode, and Plan to implement the specification
    IMPLEMENTATION (Go)
      This is the actual code of the node
    TESTS (Go)
      This is the tests for the node that verify the code meets the specification
  ChildNodes: Node[]
  ParentNode: Node
```

## Node is a workspace

A single node should map to a single Antigravity Workspace. A NODE IS A WORKSPACE. The WORKSPACE shoule only focus on the conxtext of the given node. It should not be reaching into child or parent nodes to change code. The other Nodes/Workspaces are READONLY.

## Traversal

We Document Down and Implement Up

### Document Down
Starting at the root node, we identify the intent and specification of the node. We then determin the inner modules of the node (abstractions, dependencies, etc) that are required to implement the node. We then repeat the process for each inner module (Node). We do this until we are at the smallest units of code (leaves).

### Implement Up
Starting from the leaves, we design, implement, and test the code. We then repeat the process for each inner module (Node). We do this until we are at the root node.

Before we leave the current node, we must update all the documentation.

### Remediation
If during the implementation process, we find that a dependency (inner module, child node) is not meeting our needs, not working as we expect, or not meeting our constraints. We follow these steps:

1. Stop
2. Mark our position in the implementation process
3. Identify the issue
4. Updated the specification of the dependency to remedy the issue
5. Update the tests to prove the issue is remedied
6. Remediate the issue in the dependency
7. Resume the implementation process and verify the issue is remedied

