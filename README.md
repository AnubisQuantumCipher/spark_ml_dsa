# Spark_ML_DSA

Pure SPARK Ada implementation of ML-DSA-87 (FIPS 204, Dilithium) post-quantum digital signatures

## Overview

Formally-verifiable implementation of the ML-DSA-87 post-quantum signature scheme with module-lattice cryptography, providing security against quantum computer attacks.

### Standards Compliance

- FIPS 204: Module-Lattice-Based Digital Signature Standard
- NIST PQC Round 3: Dilithium

### Key Features

- ML-DSA-87 parameter set (Category 5 security)
- Post-quantum security (lattice-based)
- Deterministic and hedged signing modes
- SHAKE256 XOF for sampling
- Formally verifiable SPARK contracts
- Constant-time critical operations

## Building

### Prerequisites

- GNAT FSF 13.1+ or GNAT Pro 24.0+
- GPRbuild
- Alire (recommended)
- GNATprove (optional, for formal verification)

### Build with Alire

```bash
alr build
```

### Build with GPRbuild

```bash
gprbuild -P spark_ml_dsa.gpr
```

### Formal Verification

```bash
gnatprove -P spark_ml_dsa.gpr --level=2 --timeout=60
```

## Testing

```bash
cd tests
gprbuild -P test_spark_ml_dsa.gpr
./obj/test_spark_ml_dsa
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): Module structure and implementation details
- [SECURITY.md](SECURITY.md): Threat model, security properties, vulnerability reporting
- [API Reference](docs/API.md): Detailed API documentation

## Security

For security vulnerabilities, see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Authors

AnubisQuantumCipher <sic.tau@pm.me>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## References

See [docs/REFERENCES.md](docs/REFERENCES.md) for academic papers, RFCs, and technical standards.
