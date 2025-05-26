# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run Commands

### Building the Project

* Build and run tests: `mvn clean test`
* Package application: `mvn package`
* Build with specific profile (AWS/Azure/GCP): `mvn package -P<profile>` (where profile is aws, azure, or gcp)

### Running Tests

* Run all tests: `mvn test`
* Run a specific test: `mvn test -Dtest=UIDOperatorVerticleTest`
* Run tests with coverage: `mvn test` (JaCoCo plugin is configured in the build)
* Run benchmarks: `mvn exec:java -Dexec.mainClass="com.uid2.operator.benchmark.BenchmarkRunner"`

### Running the Application Locally

* Run standalone local mode: `mvn clean compile exec:java -Dvertx-config-path=conf/local-config.json`
* Run integration mode: `mvn clean compile exec:java -Dvertx-config-path=conf/integ-config.json`

### Docker Commands

* Build Docker image: `docker build -t uid2-operator --build-arg JAR_VERSION=<version> .`
* Run Docker container: `docker run -it -p 8080:8080 uid2-operator:latest`
* Run vulnerability scan: `wsl trivy fs .` or `wsl trivy image <image reference>`

## Architecture Overview

UID2 Operator is a Java-based service built on the Vert.x framework that provides identity services for the Unified ID 2.0 ecosystem.

### Key Components

1. **Main Entry Point**: `com.uid2.operator.Main` - Sets up the application, verticles, and component dependencies.

2. **Verticles**: Following Vert.x's event-driven architecture pattern:
   * `UIDOperatorVerticle` - Primary service verticle handling HTTP requests
   * `StatsCollectorVerticle` - Collects and manages statistics

3. **Core Services**: 
   * `UIDOperatorService` - Implements token generation, validation, and mapping
   * `KeyManager` - Manages encryption keys and rotation
   * `OptOutStore` - Handles user opt-out information
   * `ConfigService` - Manages configuration and settings

4. **Security Components**:
   * `EncryptedTokenEncoder` - Handles token encryption/decryption
   * `SecureLinkValidatorService` - Validates secure links

### Data Flow

1. **Token Generation**:
   * Client sends identity data (email/phone hash)
   * Service checks opt-out status
   * Hash generation with salt
   * Creation of two tokens: advertising token and refresh token

2. **Token Refresh**:
   * Client sends refresh token for validation
   * Service generates new advertising token if valid

3. **Identity Mapping**:
   * Maps raw identities to advertising IDs
   * Used for joining identity data across systems

### Configuration

The application uses JSON configuration files in the `conf/` directory. Different configurations are available for:
* Local debugging (`local-config.json`)
* Integration testing (`integ-config.json`)
* Docker environments (`docker-config.json`)
* E2E testing configurations (various e2e config files)

## Important Design Patterns

1. **Vert.x Verticle Pattern**: Asynchronous, event-driven architecture for handling concurrent requests

2. **Rotating Store Pattern**: Used for keys, salts, and clients to support secure rotation and updates

3. **Handler Pattern**: Used for asynchronous operations with callbacks

4. **Factory Pattern**: Used for creating components like ConfigRetriever

5. **Cloud Provider Abstraction**: Allows operation in different cloud environments (AWS, Azure, GCP)

## Testing Approach

The project uses JUnit 5 for unit testing and includes:
* Verticle tests that test HTTP endpoints
* Service-level unit tests
* Integration tests for component interactions
* Benchmark tests using JMH for performance analysis

Test resources are in `src/test/resources` with mock data for keys, salts, and client information.