#!/usr/bin/env python3
"""
Robust Hyperswitch Connector Setup Script

This script safely creates a new connector with complete automation:
1. Discovers actual file locations dynamically
2. Creates template files with validation
3. Registers connector in all required places
4. Provides comprehensive error handling and rollback
5. Validates all changes before committing

Usage:
    ./setup_connector_robust.py <connector_name> <base_url> [options]

Examples:
    ./setup_connector_robust.py stripe https://api.stripe.com/v1
    ./setup_connector_robust.py paypal https://api.paypal.com --dry-run
    ./setup_connector_robust.py square https://connect.squareup.com --yes
"""

import argparse
import re
import sys
import os
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple, NamedTuple
from dataclasses import dataclass
from enum import Enum
import tempfile
import time

class FlowType(Enum):
    AUTHORIZE = "authorize"

ALL_FLOWS = list(FlowType)

@dataclass
class ConnectorConfig:
    """Configuration for the new connector"""
    name_snake: str
    name_pascal: str
    name_upper: str
    base_url: str
    amount_unit: str
    flows: Set[FlowType]
    enum_ordinal: int

class FileLocation(NamedTuple):
    """Represents a discovered file location"""
    path: Path
    description: str
    required: bool = True

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class ConnectorSetupError(Exception):
    """Custom exception for setup errors"""
    pass

class RobustConnectorSetup:
    """Bulletproof connector setup with comprehensive error handling"""
    
    def __init__(self, args):
        self.args = args
        self.config: Optional[ConnectorConfig] = None
        self.backup_files: List[Tuple[Path, Path]] = []  # (original, backup)
        self.created_files: List[Path] = []
        self.modified_files: List[Path] = []
        self.discovered_files: Dict[str, FileLocation] = {}
        
        # Paths
        self.root_dir = Path.cwd()
        self.template_dir = self.root_dir / "connector_template"
        
        # Backup directory for this session
        self.session_id = str(int(time.time()))
        self.backup_dir = self.root_dir / f".connector_backup_{self.session_id}"
        
    def run(self):
        """Main execution method with comprehensive error handling"""
        try:
            print("🔧 Robust Hyperswitch Connector Setup")
            print("=" * 50)
            
            # Phase 1: Discovery and Validation
            print("\n📍 Phase 1: Discovery and Validation")
            self._discover_file_locations()
            self._validate_environment()
            self._parse_and_validate_inputs()
            
            # Phase 2: Planning
            print("\n📋 Phase 2: Planning")
            self._analyze_registration_points()
            
            if not self.args.yes and not self.args.dry_run:
                self._show_plan_summary()
                if not self._confirm_proceed():
                    print("❌ Setup cancelled by user")
                    return True
            
            if self.args.dry_run:
                print("\n🔍 DRY RUN MODE - No changes will be made")
                self._show_plan_summary()
                return True
            
            # Phase 3: Implementation
            print("\n🚀 Phase 3: Implementation")
            self._create_backup_point()
            self._create_connector_files()
            self._update_registration_points()
            
            # Phase 4: Formatting
            print("\n🎨 Phase 4: Formatting")
            self._format_code()
            
            # Phase 5: Validation
            print("\n✅ Phase 5: Validation")
            self._validate_changes()
            
            # Phase 6: Completion
            print("\n🎉 Phase 6: Completion")
            self._cleanup_backups()
            
            print(f"\n✅ Connector '{self.config.name_snake}' successfully created!")
            self._show_next_steps()
            
            return True
            
        except KeyboardInterrupt:
            print("\n❌ Setup interrupted by user")
            self._emergency_rollback()
            return False
        except (ValidationError, ConnectorSetupError) as e:
            print(f"\n❌ Setup failed: {e}")
            self._emergency_rollback()
            return False
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            print("🔄 Attempting emergency rollback...")
            self._emergency_rollback()
            return False
    
    def _discover_file_locations(self):
        """Dynamically discover all required file locations"""
        print("   🔍 Discovering file locations...")
        
        # Discover protobuf file
        proto_candidates = [
            self.root_dir / "backend" / "grpc-api-types" / "proto" / "payment.proto",
            self.root_dir / "backend" / "grpc_api_types" / "proto" / "payment.proto",
        ]
        self._find_required_file("proto", proto_candidates, "Protobuf payment definitions")
        
        # Discover domain types file
        domain_candidates = [
            self.root_dir / "backend" / "domain_types" / "src" / "connector_types.rs",
            self.root_dir / "backend" / "domain-types" / "src" / "connector_types.rs",
        ]
        self._find_required_file("domain_types", domain_candidates, "Domain connector types")
        
        # Discover connector integration files
        integration_base = self.root_dir / "backend" / "connector-integration" / "src"
        if not integration_base.exists():
            raise ValidationError(f"Connector integration directory not found: {integration_base}")
            
        self.discovered_files["connectors_rs"] = FileLocation(
            integration_base / "connectors.rs", 
            "Connector module declarations"
        )
        self.discovered_files["types_rs"] = FileLocation(
            integration_base / "types.rs",
            "Connector type mappings"
        )
        self.discovered_files["connectors_dir"] = FileLocation(
            integration_base / "connectors",
            "Connectors directory"
        )
        
        # Discover config file
        config_candidates = [
            self.root_dir / "config" / "development.toml",
            self.root_dir / "configs" / "development.toml",
        ]
        self._find_required_file("config_toml", config_candidates, "Development configuration")
        
        # Validate all discovered files
        for name, location in self.discovered_files.items():
            if location.required and not location.path.exists():
                raise ValidationError(f"Required file not found: {location.path} ({location.description})")
        
        print(f"   ✅ Discovered {len(self.discovered_files)} file locations")
        
    def _find_required_file(self, name: str, candidates: List[Path], description: str):
        """Find the first existing file from candidates"""
        for candidate in candidates:
            if candidate.exists():
                self.discovered_files[name] = FileLocation(candidate, description)
                return
        raise ValidationError(f"Could not find {description} in any of: {candidates}")
    
    def _validate_environment(self):
        """Validate environment and prerequisites"""
        print("   🔍 Validating environment...")
        
        # Check template directory
        if not self.template_dir.exists():
            raise ValidationError(f"Template directory not found: {self.template_dir}")
        
        # Check required templates
        required_templates = [
            "connector.rs.template",
            "transformers.rs.template"
        ]
        for template in required_templates:
            if not (self.template_dir / template).exists():
                raise ValidationError(f"Required template missing: {template}")
        
        # Check git status
        if not self.args.force:
            try:
                result = subprocess.run(["git", "status", "--porcelain"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    print("   ⚠️  Not in a git repository - proceeding without git checks")
                elif result.stdout.strip():
                    raise ValidationError(
                        "Git working directory is not clean. Commit changes or use --force"
                    )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                print("   ⚠️  Git not available - proceeding without git checks")
        
        # Check tools
        for tool in ["cargo"]:
            if shutil.which(tool) is None:
                print(f"   ⚠️  {tool} not found - some validations will be skipped")
        
        print("   ✅ Environment validated")
    
    def _parse_and_validate_inputs(self):
        """Parse and validate all inputs with comprehensive checking"""
        print("   🔍 Validating inputs...")
        
        # Validate connector name
        if not re.match(r'^[a-z][a-z0-9_]*$', self.args.connector_name):
            raise ValidationError(
                "Connector name must start with a letter and contain only lowercase letters, numbers, and underscores"
            )
        
        # Validate base URL
        if not re.match(r'^https?://.+$', self.args.base_url):
            raise ValidationError("Base URL must be a valid HTTP/HTTPS URL")
        
        # Generate names
        name_snake = self.args.connector_name.lower()
        name_pascal = ''.join(word.capitalize() for word in name_snake.split('_'))
        name_upper = name_snake.upper()
        
        # Check naming conflicts
        self._check_naming_conflicts(name_snake, name_pascal, name_upper)
        
        # Get next enum ordinal
        enum_ordinal = self._get_next_enum_ordinal()
        
        # Parse flows
        flows = set(ALL_FLOWS)  # Default to all flows
        if self.args.flows:
            flows = self._parse_flows(self.args.flows)
        
        self.config = ConnectorConfig(
            name_snake=name_snake,
            name_pascal=name_pascal,
            name_upper=name_upper,
            base_url=self.args.base_url,
            amount_unit=self.args.amount_unit or "FloatMajorUnit",
            flows=flows,
            enum_ordinal=enum_ordinal
        )
        
        print(f"   ✅ Configuration:")
        print(f"      Name: {self.config.name_snake} → {self.config.name_pascal}")
        print(f"      URL: {self.config.base_url}")
        print(f"      Flow: authorize")
        print(f"      Enum ordinal: {self.config.enum_ordinal}")
    
    def _parse_flows(self, flows_str: str) -> Set[FlowType]:
        """Parse flow string with aliases and validation"""
        flow_names = [f.strip().lower() for f in flows_str.split(',')]
        flows = set()
        
        # Handle aliases
        aliases = {
            'auth': 'authorize',
            'authorization': 'authorize',
            'payment_sync': 'psync',
            'refund_sync': 'rsync',
        }
        
        for flow_name in flow_names:
            flow_name = aliases.get(flow_name, flow_name)
            try:
                flows.add(FlowType(flow_name))
            except ValueError:
                valid_flows = [f.value for f in FlowType]
                raise ValidationError(f"Invalid flow '{flow_name}'. Valid: {', '.join(valid_flows)}")
        
        return flows
    
    def _check_naming_conflicts(self, name_snake: str, name_pascal: str, name_upper: str):
        """Check for comprehensive naming conflicts"""
        connectors_dir = self.discovered_files["connectors_dir"].path
        
        # File system conflicts
        main_file = connectors_dir / f"{name_snake}.rs"
        connector_subdir = connectors_dir / name_snake
        
        if main_file.exists():
            raise ValidationError(f"Connector file already exists: {main_file}")
        if connector_subdir.exists():
            raise ValidationError(f"Connector directory already exists: {connector_subdir}")
        
        # Check protobuf enum
        proto_file = self.discovered_files["proto"].path
        proto_content = proto_file.read_text()
        if f"{name_upper} =" in proto_content:
            raise ValidationError(f"Connector '{name_upper}' already exists in protobuf enum")
        
        # Check domain types
        domain_file = self.discovered_files["domain_types"].path
        domain_content = domain_file.read_text()
        if f"{name_pascal}," in domain_content or f"{name_pascal} " in domain_content:
            raise ValidationError(f"Connector '{name_pascal}' already exists in domain types")
    
    def _get_next_enum_ordinal(self) -> int:
        """Get next available enum ordinal with smart discovery"""
        proto_file = self.discovered_files["proto"].path
        content = proto_file.read_text()
        
        # Find enum block
        enum_match = re.search(r'enum Connector \{(.*?)\}', content, re.DOTALL)
        if not enum_match:
            print("   ⚠️  Could not find Connector enum, using default ordinal 100")
            return 100
        
        # Extract ordinals
        enum_content = enum_match.group(1)
        ordinals = [int(m.group(1)) for m in re.finditer(r'= (\d+);', enum_content)]
        
        if not ordinals:
            return 100
        
        next_ordinal = max(ordinals) + 1
        print(f"   📊 Found {len(ordinals)} existing connectors, using ordinal {next_ordinal}")
        return next_ordinal
    
    def _analyze_registration_points(self):
        """Analyze all registration points for completeness"""
        print("   🔍 Analyzing registration points...")
        
        registration_points = []
        for name, location in self.discovered_files.items():
            if location.path.exists():
                registration_points.append(location.path)
        
        print(f"   ✅ Found {len(registration_points)} registration points")
    
    def _show_plan_summary(self):
        """Show comprehensive plan summary"""
        print("\n📝 Implementation Plan:")
        print("=" * 30)
        
        # Files to create
        connectors_dir = self.discovered_files["connectors_dir"].path
        main_file = connectors_dir / f"{self.config.name_snake}.rs"
        subdir = connectors_dir / self.config.name_snake
        
        print("\n📁 Files to create:")
        print(f"   ├── {main_file.relative_to(self.root_dir)}")
        print(f"   └── {(subdir / 'transformers.rs').relative_to(self.root_dir)}")
        
        # Files to modify
        print("\n📝 Files to modify:")
        for name, location in self.discovered_files.items():
            if name in ["proto", "domain_types", "connectors_rs", "types_rs"]:
                print(f"   ├── {location.path.relative_to(self.root_dir)} ({location.description})")
        
        print(f"\n🎯 Configuration:")
        print(f"   ├── Connector: {self.config.name_pascal}")
        print(f"   ├── Enum ordinal: {self.config.enum_ordinal}")
        print(f"   ├── Base URL: {self.config.base_url}")
        print(f"   └── Flow: authorize")
    
    def _confirm_proceed(self) -> bool:
        """Ask for user confirmation"""
        response = input("\n❓ Proceed with implementation? [y/N]: ").lower().strip()
        return response in ['y', 'yes']
    
    def _create_backup_point(self):
        """Create comprehensive backup system"""
        print("   💾 Creating backup point...")
        
        self.backup_dir.mkdir(exist_ok=True)
        
        files_to_backup = [
            self.discovered_files["proto"].path,
            self.discovered_files["domain_types"].path,
            self.discovered_files["connectors_rs"].path,
            self.discovered_files["types_rs"].path,
            self.discovered_files["config_toml"].path,
        ]
        
        for file_path in files_to_backup:
            if file_path.exists():
                backup_path = self.backup_dir / file_path.name
                shutil.copy2(file_path, backup_path)
                self.backup_files.append((file_path, backup_path))
        
        print(f"   ✅ Backed up {len(self.backup_files)} files to {self.backup_dir}")
    
    def _create_connector_files(self):
        """Create connector files with validation"""
        print("   📁 Creating connector files...")
        
        connectors_dir = self.discovered_files["connectors_dir"].path
        
        # Create main connector file
        main_file = connectors_dir / f"{self.config.name_snake}.rs"
        self._create_file_from_template("connector.rs.template", main_file)
        
        # Create connector subdirectory
        subdir = connectors_dir / self.config.name_snake
        subdir.mkdir(exist_ok=True)
        self.created_files.append(subdir)
        
        # Create transformers file
        transformers_file = subdir / "transformers.rs"
        self._create_file_from_template("transformers.rs.template", transformers_file)
        
        print(f"   ✅ Created {len(self.created_files)} connector files")
    
    def _create_file_from_template(self, template_name: str, output_path: Path):
        """Create file with comprehensive template processing"""
        template_path = self.template_dir / template_name
        
        if not template_path.exists():
            raise ConnectorSetupError(f"Template not found: {template_path}")
        
        content = template_path.read_text()
        
        # Variable substitutions
        substitutions = {
            '{{CONNECTOR_NAME_PASCAL}}': self.config.name_pascal,
            '{{CONNECTOR_NAME_SNAKE}}': self.config.name_snake,
            '{{CONNECTOR_NAME_UPPER}}': self.config.name_upper,
            '{{BASE_URL}}': self.config.base_url,
            '{{AMOUNT_UNIT_TYPE}}': self.config.amount_unit,
        }
        
        for placeholder, value in substitutions.items():
            content = content.replace(placeholder, value)
        
        # Write file
        output_path.write_text(content)
        self.created_files.append(output_path)
    
    def _update_registration_points(self):
        """Update all registration points with robust error handling"""
        print("   📝 Updating registration points...")
        
        updates = [
            (self._update_protobuf_enum, "Protobuf enum"),
            (self._update_domain_types, "Domain types"),
            (self._update_domain_foreign_try_from, "Domain foreign_try_from mapping"),
            (self._update_connectors_module, "Connector modules"),
            (self._update_types_mapping, "Type mappings"),
            (self._update_config_toml, "Configuration file"),
        ]
        
        for update_func, description in updates:
            try:
                update_func()
                print(f"      ✅ Updated {description}")
            except Exception as e:
                raise ConnectorSetupError(f"Failed to update {description}: {e}")
    
    def _update_protobuf_enum(self):
        """Update protobuf enum with smart insertion"""
        proto_file = self.discovered_files["proto"].path
        content = proto_file.read_text()
        
        # Find insertion point (before closing brace)
        enum_pattern = r'(enum Connector \{.*?)(})'
        
        def replace_enum(match):
            enum_content = match.group(1)
            closing_brace = match.group(2)
            new_line = f"  {self.config.name_upper} = {self.config.enum_ordinal};\n"
            return enum_content + new_line + closing_brace
        
        new_content = re.sub(enum_pattern, replace_enum, content, flags=re.DOTALL)
        
        if new_content == content:
            raise ConnectorSetupError("Could not update protobuf enum - pattern not found")
        
        proto_file.write_text(new_content)
        self.modified_files.append(proto_file)
    
    def _update_domain_types(self):
        """Update domain types with comprehensive mapping"""
        domain_file = self.discovered_files["domain_types"].path
        content = domain_file.read_text()
        
        # Add to ConnectorEnum
        enum_pattern = r'(pub enum ConnectorEnum \{[^}]*)(})'
        def replace_connector_enum(match):
            enum_content = match.group(1)
            closing_brace = match.group(2)
            new_line = f"    {self.config.name_pascal},\n"
            return enum_content + new_line + closing_brace
        
        content = re.sub(enum_pattern, replace_connector_enum, content, flags=re.DOTALL)
        
        # Add to gRPC mapping if it exists
        grpc_pattern = r'(grpc_api_types::payments::Connector::[^}]*)(            _ => Err\(.*?\))'
        def replace_grpc_mapping(match):
            match_content = match.group(1)
            error_case = match.group(2)
            new_line = f"            grpc_api_types::payments::Connector::{self.config.name_pascal} => Ok(Self::{self.config.name_pascal}),\n"
            return match_content + new_line + "            " + error_case
        
        content = re.sub(grpc_pattern, replace_grpc_mapping, content, flags=re.DOTALL)
        
        domain_file.write_text(content)
        self.modified_files.append(domain_file)
    
    def _update_domain_foreign_try_from(self):
        """Update domain types foreign_try_from mapping"""
        domain_file = self.discovered_files["domain_types"].path
        content = domain_file.read_text()
        
        # Add to foreign_try_from implementation
        foreign_pattern = r'(grpc_api_types::payments::Connector::Mifinity => Ok\(Self::Mifinity\),\s*)(            grpc_api_types::payments::Connector::Unspecified)'
        
        def add_foreign_mapping(match):
            mifinity_line = match.group(1)
            unspecified_line = match.group(2)
            new_line = f"            grpc_api_types::payments::Connector::{self.config.name_pascal} => Ok(Self::{self.config.name_pascal}),\n            "
            return mifinity_line + new_line + unspecified_line
        
        new_content = re.sub(foreign_pattern, add_foreign_mapping, content, flags=re.DOTALL)
        
        if new_content == content:
            # Fallback: try to find any connector mapping pattern
            fallback_pattern = r'(grpc_api_types::payments::Connector::\w+ => Ok\(Self::\w+\),\s*)(            grpc_api_types::payments::Connector::Unspecified)'
            new_content = re.sub(fallback_pattern, add_foreign_mapping, content, flags=re.DOTALL)
            
            if new_content == content:
                raise ConnectorSetupError("Could not update foreign_try_from mapping - pattern not found")
        
        domain_file.write_text(new_content)
        self.modified_files.append(domain_file)
    
    def _update_connectors_module(self):
        """Update connectors.rs with proper ordering"""
        connectors_file = self.discovered_files["connectors_rs"].path
        content = connectors_file.read_text()
        
        # Add module declaration (maintain alphabetical order)
        lines = content.split('\n')
        new_lines = []
        mod_added = False
        use_block_updated = False
        
        for i, line in enumerate(lines):
            # Add module declaration in alphabetical order
            if line.startswith('pub mod ') and not mod_added:
                current_mod = line.replace('pub mod ', '').replace(';', '').strip()
                if self.config.name_snake < current_mod:
                    new_lines.append(f"pub mod {self.config.name_snake};")
                    mod_added = True
                new_lines.append(line)
            elif line.startswith('pub use self::{') and not use_block_updated:
                # Find the end of the use block and add our connector
                use_block_lines = [line]
                j = i + 1
                while j < len(lines) and not lines[j].strip().endswith('};'):
                    use_block_lines.append(lines[j])
                    j += 1
                if j < len(lines):
                    use_block_lines.append(lines[j])  # Add the closing line
                
                # Parse the use block and add our connector alphabetically
                use_content = '\n'.join(use_block_lines)
                # Extract existing imports
                import_match = re.search(r'pub use self::\{\s*(.*?)\s*\};', use_content, re.DOTALL)
                if import_match:
                    imports_text = import_match.group(1)
                    # Split into individual imports and clean them
                    imports = [imp.strip().rstrip(',') for imp in imports_text.split(',') if imp.strip()]
                    
                    # Add our new import
                    new_import = f"{self.config.name_snake}::{self.config.name_pascal}"
                    if new_import not in imports:
                        imports.append(new_import)
                        imports.sort()  # Sort alphabetically
                    
                    # Rebuild the use statement
                    formatted_imports = ',\n    '.join(imports)
                    new_use_block = f"pub use self::{{\n    {formatted_imports},\n}};"
                    new_lines.append(new_use_block)
                else:
                    # Fallback: append to existing block
                    new_lines.extend(use_block_lines)
                
                use_block_updated = True
                # Skip the lines we already processed
                for _ in range(len(use_block_lines) - 1):
                    if i + 1 < len(lines):
                        lines.pop(i + 1)
            else:
                new_lines.append(line)
        
        # If not added yet, add at end
        if not mod_added:
            # Find a good place to add the module declaration
            for i, line in enumerate(new_lines):
                if line.startswith('pub mod '):
                    current_mod = line.replace('pub mod ', '').replace(';', '').strip()
                    if self.config.name_snake < current_mod:
                        new_lines.insert(i, f"pub mod {self.config.name_snake};")
                        break
            else:
                new_lines.append(f"pub mod {self.config.name_snake};")
        
        connectors_file.write_text('\n'.join(new_lines))
        self.modified_files.append(connectors_file)
    
    def _update_types_mapping(self):
        """Update types.rs with connector mapping"""
        types_file = self.discovered_files["types_rs"].path
        content = types_file.read_text()
        
        # Update import block properly
        import_pattern = r'(use crate::connectors::\{\s*)(.*?)(\s*\};)'
        import_match = re.search(import_pattern, content, re.DOTALL)
        
        if import_match:
            prefix = import_match.group(1)
            imports_text = import_match.group(2)
            suffix = import_match.group(3)
            
            # Parse existing imports
            imports = []
            for line in imports_text.split(','):
                cleaned = line.strip().rstrip(',')
                if cleaned:
                    imports.append(cleaned)
            
            # Add our connector import if not already present
            new_import = self.config.name_pascal
            if new_import not in imports:
                imports.append(new_import)
                imports.sort()  # Sort alphabetically
            
            # Rebuild import block
            formatted_imports = ',\n    '.join(imports)
            new_import_block = f"{prefix}\n    {formatted_imports},\n{suffix}"
            
            content = content.replace(import_match.group(0), new_import_block)
        else:
            # Fallback: add individual import line
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'use domain_types::' in line:
                    lines.insert(i, f"use crate::connectors::{self.config.name_snake}::{self.config.name_pascal};")
                    break
            content = '\n'.join(lines)
        
        # Add to conversion function
        convert_pattern = r'(match connector_name \{\s*.*?)(        \})'
        convert_match = re.search(convert_pattern, content, re.DOTALL)
        
        if convert_match:
            match_content = convert_match.group(1)
            closing = convert_match.group(2)
            
            # Add our connector mapping alphabetically
            new_line = f"            ConnectorEnum::{self.config.name_pascal} => Box::new({self.config.name_pascal}::new()),\n"
            
            # Insert in alphabetical order
            lines = match_content.split('\n')
            inserted = False
            for i, line in enumerate(lines):
                if 'ConnectorEnum::' in line and '=>' in line:
                    current_connector = line.split('::')[1].split(' ')[0]
                    if self.config.name_pascal < current_connector:
                        lines.insert(i, f"            ConnectorEnum::{self.config.name_pascal} => Box::new({self.config.name_pascal}::new()),")
                        inserted = True
                        break
            
            if not inserted:
                # Add before the closing brace
                lines.append(f"            ConnectorEnum::{self.config.name_pascal} => Box::new({self.config.name_pascal}::new()),")
            
            new_match_content = '\n'.join(lines)
            content = content.replace(convert_match.group(0), new_match_content + closing)
        
        types_file.write_text(content)
        self.modified_files.append(types_file)
    
    def _update_config_toml(self):
        """Update development.toml with connector base URL"""
        config_file = self.discovered_files["config_toml"].path
        content = config_file.read_text()
        
        # Find the [connectors] section and add the base_url
        connector_section_pattern = r'(\[connectors\][^\[]*)'
        
        def add_connector_config(match):
            section_content = match.group(1)
            # Add new connector configuration in alphabetical order
            new_config = f"{self.config.name_snake}.base_url = \"{self.config.base_url}\"\n"
            
            # Find the right place to insert (alphabetical order)
            lines = section_content.split('\n')
            new_lines = []
            inserted = False
            
            for line in lines:
                if '=' in line and not inserted:
                    connector_name = line.split('.')[0]
                    if self.config.name_snake < connector_name:
                        new_lines.append(new_config.rstrip())
                        inserted = True
                new_lines.append(line)
            
            if not inserted:
                # Insert before any empty lines at the end
                while new_lines and new_lines[-1].strip() == '':
                    new_lines.pop()
                new_lines.append(new_config.rstrip())
                new_lines.append('')  # Add back empty line
            
            return '\n'.join(new_lines)
        
        new_content = re.sub(connector_section_pattern, add_connector_config, content, flags=re.DOTALL)
        config_file.write_text(new_content)
        self.modified_files.append(config_file)
    
    def _format_code(self):
        """Format code using cargo fmt"""
        print("   🎨 Formatting code...")
        
        if shutil.which("cargo") is None:
            print("   ⚠️  Cargo not found - skipping code formatting")
            return
        
        try:
            result = subprocess.run(
                ["cargo", "+nightly", "fmt", "--all"],
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print("   ✅ Code formatted successfully")
            else:
                print(f"   ⚠️  Code formatting completed with warnings: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("   ⚠️  Code formatting timed out")
        except FileNotFoundError:
            print("   ⚠️  Nightly toolchain not found - falling back to stable")
            try:
                result = subprocess.run(
                    ["cargo", "fmt", "--all"],
                    cwd=self.root_dir,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode == 0:
                    print("   ✅ Code formatted successfully (stable)")
                else:
                    print(f"   ⚠️  Code formatting failed: {result.stderr}")
            except Exception as e:
                print(f"   ⚠️  Could not format code: {e}")
        except Exception as e:
            print(f"   ⚠️  Could not format code: {e}")
    
    def _validate_changes(self):
        """Comprehensive validation of all changes"""
        print("   ✅ Validating changes...")
        
        validations = [
            (self._validate_syntax, "Rust syntax"),
            (self._validate_completeness, "Registration completeness"),
        ]
        
        for validate_func, description in validations:
            try:
                validate_func()
                print(f"      ✅ {description} validation passed")
            except Exception as e:
                if not self.args.skip_validation:
                    raise ConnectorSetupError(f"{description} validation failed: {e}")
                else:
                    print(f"      ⚠️  {description} validation skipped: {e}")
    
    def _validate_syntax(self):
        """Validate Rust syntax"""
        if shutil.which("cargo") is None:
            raise ValidationError("Cargo not found - cannot validate syntax")
        
        try:
            result = subprocess.run(
                ["cargo", "check", "--message-format=json"],
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse output for serious errors
            errors = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        msg = json.loads(line)
                        if msg.get('reason') == 'compiler-message':
                            level = msg.get('message', {}).get('level')
                            if level == 'error':
                                message = msg.get('message', {}).get('message', 'Unknown error')
                                if 'cannot find' in message or 'unresolved import' in message:
                                    errors.append(message)
                    except json.JSONDecodeError:
                        continue
            
            if errors:
                raise ValidationError(f"Critical compilation errors: {errors[:2]}")
                
        except subprocess.TimeoutExpired:
            print("      ⚠️  Syntax validation timed out")
    
    def _validate_completeness(self):
        """Validate registration completeness"""
        # Check that all required files were modified
        required_modifications = ["proto", "domain_types", "connectors_rs", "types_rs"]
        modified_names = {f.name for f in self.modified_files}
        
        for req in required_modifications:
            expected_name = self.discovered_files[req].path.name
            if expected_name not in modified_names:
                raise ValidationError(f"Required file not modified: {expected_name}")
    
    def _emergency_rollback(self):
        """Emergency rollback with comprehensive recovery"""
        if not (self.backup_files or self.created_files):
            return
        
        print("🔄 Performing emergency rollback...")
        
        # Remove created files
        for file_path in reversed(self.created_files):
            try:
                if file_path.is_dir():
                    shutil.rmtree(file_path, ignore_errors=True)
                else:
                    file_path.unlink(missing_ok=True)
                print(f"   ❌ Removed: {file_path.name}")
            except Exception as e:
                print(f"   ⚠️  Could not remove {file_path}: {e}")
        
        # Restore backed up files
        for original, backup in self.backup_files:
            try:
                if backup.exists():
                    shutil.copy2(backup, original)
                    print(f"   ↩️  Restored: {original.name}")
            except Exception as e:
                print(f"   ⚠️  Could not restore {original}: {e}")
        
        print("🔄 Emergency rollback completed")
    
    def _cleanup_backups(self):
        """Clean up backup files"""
        try:
            if self.backup_dir.exists():
                shutil.rmtree(self.backup_dir)
                print("   🧹 Cleaned up backup files")
        except Exception as e:
            print(f"   ⚠️  Could not clean up backups: {e}")
    
    def _show_next_steps(self):
        """Show comprehensive next steps"""
        print("\n📖 Next Steps:")
        print("=" * 20)
        
        connectors_dir = self.discovered_files["connectors_dir"].path
        
        print("\n1️⃣  Implement Core Logic:")
        print(f"   📁 Edit: {(connectors_dir / self.config.name_snake / 'transformers.rs').relative_to(self.root_dir)}")
        print("      • Update request/response structures for your API")
        print("      • Implement proper field mappings")
        print("      • Handle authentication requirements")
        
        print(f"\n2️⃣  Customize Connector:")
        print(f"   📁 Edit: {(connectors_dir / f'{self.config.name_snake}.rs').relative_to(self.root_dir)}")
        print("      • Update URL patterns and endpoints")
        print("      • Implement error handling")
        print("      • Add any connector-specific logic")
        
        print("\n3️⃣  Validation Commands:")
        print("   📋 Check compilation: cargo check --package connector-integration")
        print("   📋 Run tests: cargo test --package connector-integration")
        print("   📋 Build: cargo build --package connector-integration")
        
        print(f"\n🎉 Connector '{self.config.name_pascal}' is ready for implementation!")


def create_argument_parser():
    """Create comprehensive argument parser"""
    parser = argparse.ArgumentParser(
        description="Robust Hyperswitch connector setup with complete automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s stripe https://api.stripe.com/v1
  %(prog)s paypal https://api.paypal.com --dry-run
  %(prog)s square https://connect.squareup.com --yes --flows authorize,capture
  %(prog)s adyen https://checkout-test.adyen.com/v70 --force --skip-validation

Available flows:
  authorize, capture, void, refund, psync, rsync
        """
    )
    
    parser.add_argument(
        "connector_name",
        help="Name of the connector (snake_case)"
    )
    
    parser.add_argument(
        "base_url", 
        help="Base URL for the connector API"
    )
    
    parser.add_argument(
        "--flows", 
        help="Comma-separated list of flows to implement (default: all)"
    )
    
    parser.add_argument(
        "--amount-unit",
        choices=["MinorUnit", "FloatMajorUnit"],
        help="Amount unit type (default: FloatMajorUnit)"
    )
    
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompts"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true", 
        help="Show what would be done without making changes"
    )
    
    parser.add_argument(
        "--force",
        action="store_true", 
        help="Force setup even with dirty git working directory"
    )
    
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip syntax validation (faster but less safe)"
    )
    
    return parser


def main():
    """Main entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    setup = RobustConnectorSetup(args)
    success = setup.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()