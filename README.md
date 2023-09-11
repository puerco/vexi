# VEXi - A (Wolfi-based) Container Image VEX Generator

VEXi (short for VEX-Image) is a command line tool that generates 
[OpenVEX](https://github.com/openvex) documents for container images based on the 
[Wolfi Linux (un)distribution](https://wolfi.dev).

| | |
| --- | --- | 
| ![OpenVEX](https://avatars.githubusercontent.com/u/121361164?s=200&v=4) | ![Wolfi](https://avatars.githubusercontent.com/u/112963370?s=200&v=4) |

To generate the VEX (Vulnerability Exploitability eXchange) data, VEXi looks
in the registry for SBOMs (Software Bill of Materials) attached to the container
image. Using the image SBOM, VEXi fetches the security advisories all the Wolfi
packages installed in the image and assembles an OpenVEX document from them.

The resulting VEX document can be used to improve security scan results with
compatible scanners such as [Trivy from Aqua](https://www.aquasec.com/products/trivy/)
or [Anchore's Grype](https://anchore.com/opensource/).

## SBOM Compatibility

By default, VEXi will try to discover SBOMs signed and attached to the image using
[sigstore's attestation specification](https://github.com/sigstore/cosign/blob/main/specs/ATTESTATION_SPEC.md). VEXi is compatible with SPDX and CycloneDX. It uses
[protobom](http://github.com/bom-squad/protobom) under the hood to parse and
query SBOM data, which means that VEXi can use any SBOM format supported by 
protobom.
