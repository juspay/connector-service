"""
Layer 1: Tree-sitter AST parsing for Rust codebase.

Parses Rust source files into structured AST data using tree-sitter,
extracting structs, enums, traits, impl blocks, functions, use statements,
macro invocations, and module declarations.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import tree_sitter_rust as tsrust
    from tree_sitter import Language, Parser
except ImportError:
    tsrust = None
    Language = None
    Parser = None


@dataclass
class StructDef:
    name: str
    visibility: str = ""
    fields: List[str] = field(default_factory=list)
    derives: List[str] = field(default_factory=list)
    line: int = 0


@dataclass
class EnumDef:
    name: str
    visibility: str = ""
    variants: List[str] = field(default_factory=list)
    derives: List[str] = field(default_factory=list)
    line: int = 0


@dataclass
class TraitDef:
    name: str
    visibility: str = ""
    methods: List[str] = field(default_factory=list)
    line: int = 0


@dataclass
class ImplBlock:
    type_name: str
    trait_name: Optional[str] = None
    methods: List[str] = field(default_factory=list)
    line: int = 0


@dataclass
class FunctionSig:
    name: str
    visibility: str = ""
    parameters: List[str] = field(default_factory=list)
    return_type: str = ""
    line: int = 0


@dataclass
class MacroCall:
    name: str
    line: int = 0


@dataclass
class FileAST:
    file_path: str
    structs: List[StructDef] = field(default_factory=list)
    enums: List[EnumDef] = field(default_factory=list)
    traits: List[TraitDef] = field(default_factory=list)
    impl_blocks: List[ImplBlock] = field(default_factory=list)
    functions: List[FunctionSig] = field(default_factory=list)
    use_statements: List[str] = field(default_factory=list)
    macro_calls: List[MacroCall] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)


def _get_text(node, source: bytes) -> str:
    """Extract text from a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _extract_visibility(node, source: bytes) -> str:
    """Extract visibility modifier from a node."""
    for child in node.children:
        if child.type == "visibility_modifier":
            return _get_text(child, source)
    return ""


def _extract_derives(node, source: bytes) -> List[str]:
    """Find derive attributes from sibling attribute_item nodes."""
    derives = []
    if node.parent is None:
        return derives
    found = False
    for sibling in node.parent.children:
        if sibling.id == node.id:
            found = True
            break
        if sibling.type == "attribute_item":
            text = _get_text(sibling, source)
            if "derive" in text:
                # Extract derive contents: #[derive(X, Y, Z)]
                start = text.find("(")
                end = text.rfind(")")
                if start != -1 and end != -1:
                    inner = text[start + 1:end]
                    for d in inner.split(","):
                        d = d.strip()
                        if d:
                            derives.append(d)
    return derives


def _extract_struct_fields(node, source: bytes) -> List[str]:
    """Extract field names from struct field_declaration children."""
    fields = []
    for child in node.children:
        if child.type == "field_declaration_list":
            for field_child in child.children:
                if field_child.type == "field_declaration":
                    for fc in field_child.children:
                        if fc.type == "field_identifier":
                            fields.append(_get_text(fc, source))
                            break
    return fields


def _extract_enum_variants(node, source: bytes) -> List[str]:
    """Extract variant names from enum_variant_list."""
    variants = []
    for child in node.children:
        if child.type == "enum_variant_list":
            for variant_child in child.children:
                if variant_child.type == "enum_variant":
                    for vc in variant_child.children:
                        if vc.type == "identifier":
                            variants.append(_get_text(vc, source))
                            break
    return variants


def _extract_trait_methods(node, source: bytes) -> List[str]:
    """Extract method names from trait declaration_list."""
    methods = []
    for child in node.children:
        if child.type == "declaration_list":
            for decl_child in child.children:
                if decl_child.type in ("function_signature_item", "function_item"):
                    for fc in decl_child.children:
                        if fc.type == "identifier":
                            methods.append(_get_text(fc, source))
                            break
    return methods


def _extract_impl_info(node, source: bytes):
    """Extract type, trait, and methods from impl block."""
    type_name = ""
    trait_name = None
    methods = []

    # Find type and trait
    children_types = [c.type for c in node.children]

    if "for" in children_types:
        # impl Trait for Type
        for_idx = children_types.index("for")
        # Trait is before 'for', Type is after
        for i in range(for_idx):
            child = node.children[i]
            if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                text = _get_text(child, source)
                trait_name = text.split("<")[0].strip()
                break
        for i in range(for_idx + 1, len(node.children)):
            child = node.children[i]
            if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                text = _get_text(child, source)
                type_name = text.split("<")[0].strip()
                break
    else:
        # impl Type
        for child in node.children:
            if child.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                text = _get_text(child, source)
                type_name = text.split("<")[0].strip()
                break

    # Extract methods from declaration_list
    for child in node.children:
        if child.type == "declaration_list":
            for decl_child in child.children:
                if decl_child.type == "function_item":
                    for fc in decl_child.children:
                        if fc.type == "identifier":
                            methods.append(_get_text(fc, source))
                            break

    return type_name, trait_name, methods


def _extract_function_sig(node, source: bytes):
    """Extract function signature: name, parameters, return_type."""
    name = ""
    parameters = []
    return_type = ""

    for child in node.children:
        if child.type == "identifier":
            name = _get_text(child, source)
        elif child.type == "parameters":
            for param_child in child.children:
                if param_child.type == "parameter":
                    param_text = _get_text(param_child, source)
                    parameters.append(param_text)
                elif param_child.type == "self_parameter":
                    parameters.append(_get_text(param_child, source))
        elif child.type in ("type_identifier", "scoped_type_identifier",
                            "generic_type", "reference_type", "primitive_type",
                            "tuple_type", "unit_type"):
            # This is likely the return type if it comes after parameters
            return_type = _get_text(child, source)

    # Check for explicit return type with ->
    text = _get_text(node, source)
    if "->" in text:
        ret_part = text.split("->", 1)[1]
        # Take up to the opening brace
        brace_idx = ret_part.find("{")
        if brace_idx != -1:
            return_type = ret_part[:brace_idx].strip()
        else:
            return_type = ret_part.strip()

    return name, parameters, return_type


class RustASTParser:
    """Parse Rust source files using tree-sitter."""

    def __init__(self):
        if tsrust is None or Parser is None:
            raise ImportError(
                "tree-sitter and tree-sitter-rust are required. "
                "Install with: pip install tree-sitter tree-sitter-rust"
            )
        self.parser = Parser(Language(tsrust.language()))

    def parse_file(self, file_path: str) -> Optional[FileAST]:
        """Parse a single Rust file into a FileAST."""
        try:
            with open(file_path, "rb") as f:
                source = f.read()
        except (OSError, IOError):
            return None

        tree = self.parser.parse(source)
        file_ast = FileAST(file_path=file_path)
        self._walk_node(tree.root_node, source, file_ast)
        return file_ast

    def _walk_node(self, node, source: bytes, file_ast: FileAST):
        """Recursively walk tree-sitter nodes and extract AST data."""
        if node.type == "struct_item":
            name = ""
            for child in node.children:
                if child.type == "type_identifier":
                    name = _get_text(child, source)
                    break
            if name:
                file_ast.structs.append(StructDef(
                    name=name,
                    visibility=_extract_visibility(node, source),
                    fields=_extract_struct_fields(node, source),
                    derives=_extract_derives(node, source),
                    line=node.start_point[0] + 1,
                ))

        elif node.type == "enum_item":
            name = ""
            for child in node.children:
                if child.type == "type_identifier":
                    name = _get_text(child, source)
                    break
            if name:
                file_ast.enums.append(EnumDef(
                    name=name,
                    visibility=_extract_visibility(node, source),
                    variants=_extract_enum_variants(node, source),
                    derives=_extract_derives(node, source),
                    line=node.start_point[0] + 1,
                ))

        elif node.type == "trait_item":
            name = ""
            for child in node.children:
                if child.type == "type_identifier":
                    name = _get_text(child, source)
                    break
            if name:
                file_ast.traits.append(TraitDef(
                    name=name,
                    visibility=_extract_visibility(node, source),
                    methods=_extract_trait_methods(node, source),
                    line=node.start_point[0] + 1,
                ))

        elif node.type == "impl_item":
            type_name, trait_name, methods = _extract_impl_info(node, source)
            if type_name:
                file_ast.impl_blocks.append(ImplBlock(
                    type_name=type_name,
                    trait_name=trait_name,
                    methods=methods,
                    line=node.start_point[0] + 1,
                ))

        elif node.type == "function_item":
            name, parameters, return_type = _extract_function_sig(node, source)
            if name:
                file_ast.functions.append(FunctionSig(
                    name=name,
                    visibility=_extract_visibility(node, source),
                    parameters=parameters,
                    return_type=return_type,
                    line=node.start_point[0] + 1,
                ))

        elif node.type == "use_declaration":
            file_ast.use_statements.append(_get_text(node, source))

        elif node.type == "macro_invocation":
            macro = self._extract_macro(node, source)
            if macro:
                file_ast.macro_calls.append(macro)

        elif node.type == "expression_statement":
            # Macros wrapped in expression statements
            for child in node.children:
                if child.type == "macro_invocation":
                    macro = self._extract_macro(child, source)
                    if macro:
                        file_ast.macro_calls.append(macro)

        elif node.type == "mod_item":
            for child in node.children:
                if child.type == "identifier":
                    file_ast.modules.append(_get_text(child, source))
                    break

        # Recurse into children
        for child in node.children:
            if node.type not in ("macro_invocation",):
                self._walk_node(child, source, file_ast)

    def _extract_macro(self, node, source: bytes) -> Optional[MacroCall]:
        """Extract macro name from a macro_invocation node."""
        for child in node.children:
            if child.type == "identifier":
                return MacroCall(
                    name=_get_text(child, source),
                    line=node.start_point[0] + 1,
                )
            elif child.type == "scoped_identifier":
                # Path-qualified macro like macros::create_all_prerequisites
                text = _get_text(child, source)
                # Extract last segment
                name = text.rsplit("::", 1)[-1]
                return MacroCall(
                    name=name,
                    line=node.start_point[0] + 1,
                )
        return None

    def parse_directory(self, directory: str, extensions: tuple = (".rs",)) -> List[FileAST]:
        """Parse all Rust files in a directory recursively."""
        file_asts = []
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    fpath = os.path.join(root, fname)
                    ast = self.parse_file(fpath)
                    if ast:
                        file_asts.append(ast)
        return file_asts

    def parse_files(self, file_paths: List[str]) -> List[FileAST]:
        """Parse a list of specific file paths."""
        file_asts = []
        for fpath in file_paths:
            ast = self.parse_file(fpath)
            if ast:
                file_asts.append(ast)
        return file_asts


def save_file_ast(file_ast: FileAST, output_dir: str):
    """Save a FileAST to JSON. Converts file path to safe name: / -> __, .rs -> .json."""
    os.makedirs(output_dir, exist_ok=True)
    safe_name = file_ast.file_path.replace("/", "__")
    if safe_name.endswith(".rs"):
        safe_name = safe_name[:-3] + ".json"
    else:
        safe_name += ".json"
    out_path = os.path.join(output_dir, safe_name)
    with open(out_path, "w") as f:
        json.dump(asdict(file_ast), f, indent=2)


def load_file_ast(json_path: str) -> FileAST:
    """Load a FileAST from a JSON file."""
    with open(json_path, "r") as f:
        data = json.load(f)

    return FileAST(
        file_path=data["file_path"],
        structs=[StructDef(**s) for s in data.get("structs", [])],
        enums=[EnumDef(**e) for e in data.get("enums", [])],
        traits=[TraitDef(**t) for t in data.get("traits", [])],
        impl_blocks=[ImplBlock(**i) for i in data.get("impl_blocks", [])],
        functions=[FunctionSig(**fn) for fn in data.get("functions", [])],
        use_statements=data.get("use_statements", []),
        macro_calls=[MacroCall(**m) for m in data.get("macro_calls", [])],
        modules=data.get("modules", []),
    )
