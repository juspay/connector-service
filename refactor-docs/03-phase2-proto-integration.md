# Phase 2: Core Proto Integration & Code Generation

## Overview
Generate new Rust code from updated proto definitions and ensure the generated types compile and integrate properly with the existing codebase.

## Completion Target
All generated code compiles successfully. gRPC server starts. Client SDKs are functional.

## Tasks (Execute in parallel)

### Task 2A: Proto Code Generation and Integration
**Assigned to**: Sub-agent Alpha  
**Dependencies**: Phase 1 completion

#### Objectives
- Generate new Rust code from proto definitions
- Ensure generated code compiles
- Update grpc-api-types crate structure

#### Steps
1. **Generate Proto Code**
   ```bash
   cd backend/grpc-api-types
   cargo clean
   buf generate proto/
   cargo build
   ```

2. **Analyze Generated Code Structure**
   ```bash
   find src/ -name "*.rs" -exec wc -l {} \; | sort -n
   ls -la src/
   ```

3. **Update lib.rs for New Modules**
   - Add pub mod declarations for new generated modules
   - Update public exports
   - Ensure feature flags are properly configured

4. **Fix Compilation Issues**
   - Resolve any missing dependencies
   - Fix import statements
   - Address any generated code issues

5. **Document Generated Code Structure**
   - Map proto files to generated Rust modules
   - Document public API surface
   - Note any significant changes from previous version

#### Deliverables
- Fully compiled grpc-api-types crate
- Updated lib.rs with new module structure
- Documentation of generated code structure
- List of any compilation fixes applied

#### Acceptance Criteria
- grpc-api-types crate compiles without errors or warnings
- All generated types are accessible
- Public API is properly exported
- No missing dependencies

---

### Task 2B: gRPC Server Code Generation and Initial Updates
**Assigned to**: Sub-agent Beta  
**Dependencies**: Task 2A completion

#### Objectives
- Update grpc-server crate for new proto definitions
- Generate new service stubs
- Ensure server code compiles with new types

#### Steps
1. **Generate Server Code**
   ```bash
   cd backend/grpc-server
   cargo clean
   cargo build
   ```

2. **Update Service Dependencies**
   ```rust
   // In Cargo.toml
   [dependencies]
   grpc-api-types = { path = "../grpc-api-types" }
   ```

3. **Update Import Statements**
   - Update all imports from grpc-api-types
   - Fix any changed type names
   - Update service trait imports

4. **Stub Out Server Handlers**
   ```rust
   // Create placeholder implementations
   impl PaymentService for PaymentServiceImpl {
       async fn authorize(&self, request: Request<PaymentServiceAuthorizeRequest>) 
           -> Result<Response<PaymentServiceAuthorizeResponse>, Status> {
           todo!("Update for new proto structure")
       }
       // ... other methods
   }
   ```

5. **Update main.rs and app.rs**
   - Fix service registration
   - Update any direct proto type usage
   - Ensure server starts without panics

#### Deliverables
- Compiling grpc-server crate (with TODO implementations)
- Updated service handler stubs
- Updated import statements
- Server startup verification

#### Acceptance Criteria
- grpc-server compiles without errors
- Server can start (even with TODO implementations)
- All service methods are stubbed out
- No import errors

---

### Task 2C: Client SDK Code Generation
**Assigned to**: Sub-agent Gamma  
**Dependencies**: Task 2A completion

#### Objectives
- Regenerate client SDK code for multiple languages
- Ensure client SDKs compile with new proto definitions
- Update SDK build processes

#### Steps
1. **Regenerate Node.js SDK**
   ```bash
   cd sdk/node-grpc-client
   npm run generate-proto
   npm run build
   ```

2. **Regenerate Python SDK**
   ```bash
   cd sdk/python-grpc-client
   make generate
   make build
   ```

3. **Regenerate Rust Client SDK**
   ```bash
   cd sdk/rust-grpc-client
   cargo build
   ```

4. **Update Client Examples**
   - Fix any changed message structures in examples
   - Update import statements
   - Ensure examples compile

5. **Document SDK Changes**
   - List breaking changes in each SDK
   - Document new message structures
   - Update SDK README files

#### Deliverables
- Regenerated client SDKs for all languages
- Updated example code
- SDK change documentation
- Build verification for all SDKs

#### Acceptance Criteria
- All client SDKs compile successfully
- Example code compiles and runs
- SDK documentation is updated
- No breaking changes in basic functionality

---

### Task 2D: Example Project Updates
**Assigned to**: Sub-agent Delta  
**Dependencies**: Task 2A, 2C completion

#### Objectives
- Update all example projects for new proto interfaces
- Ensure examples compile and run
- Update example documentation

#### Steps
1. **Update Rust Examples**
   ```bash
   cd examples/example-rs
   cargo build
   # Fix any compilation issues
   ```

2. **Update JavaScript Examples**
   ```bash
   cd examples/example-js
   npm install
   npm run build
   ```

3. **Update Python Examples**
   ```bash
   cd examples/example-py
   python -m pip install -r requirements.txt
   python main.py --help
   ```

4. **Update Other Language Examples**
   - Check Haskell examples
   - Update any CLI examples
   - Fix TUI examples

5. **Update Example Documentation**
   - Update README files with new message structures
   - Fix any outdated API calls
   - Add examples for new features

#### Deliverables
- All example projects compile and run
- Updated example documentation
- Fixed any breaking API changes
- Verified example functionality

#### Acceptance Criteria
- All examples compile without errors
- Examples can connect to server successfully
- Documentation reflects new API structure
- No runtime errors in basic functionality

---

## Phase 2 Completion Criteria

### Must Complete Before Phase 3
1. All generated code compiles successfully
2. gRPC server starts without errors
3. Client SDKs are functional
4. Basic connectivity is verified

### Handoff to Phase 3
- **Compiled grpc-api-types** with new proto definitions
- **Server stub implementations** ready for real logic
- **Working client SDKs** for testing
- **Functional examples** for verification

### Risk Mitigation
- **Generated code issues**: Keep detailed logs of generation process
- **Breaking changes**: Document all changes for Phase 3 teams
- **Compilation failures**: Provide exact error messages and context

### Efficiency Focus
- **Get compiling first**: Focus on compilation before optimization
- **Test immediately**: Verify each component as it becomes available
- **Parallel generation**: Run all code generation simultaneously where possible
- **Quick validation**: Test basic functionality immediately

### Dependencies for Phase 3
- All teams need access to compiled grpc-api-types
- Server implementation team needs stub handlers
- Domain types team needs generated message structures
- Testing team needs working examples