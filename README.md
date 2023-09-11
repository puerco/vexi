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

## Sample Run

To generate VEX data simply run `vexi generate` and point to a container image:

```
go run .  generate cgr.dev/chainguard/node@sha256:3afbc808e0fe2af41f9183915f19d843c6b7e9ae3aa321f4bd9bbc1145172927
INFO[0000] cloning advisory data...                     
WARN[0005] ignoring attached document of type https://slsa.dev/provenance/v1 
WARN[0005] ignoring attached document of unsupported type https://apko.dev/image-configuration 
INFO[0005] Downloaded 1 SBOMs from image cgr.dev/chainguard/node@sha256:3afbc808e0fe2af41f9183915f19d843c6b7e9ae3aa321f4bd9bbc1145172927 
INFO[0005] Found 23 wolfi packages in image SBOM        
INFO[0005] Found 5 package advisories                   
INFO[0005] Built 5 OpenVEX documents from advisories
```

This should output VEX data for the image:

```json    
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "merged-vex-f16421c52429f443cc72b9b0378ee771c26979b6c3c7a6327bfa66a7090aff98",
  "author": "Unknown Author",
  "timestamp": "2023-09-11T00:51:52.111962-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2010-4756"
      },
      "timestamp": "2023-03-06T17:47:28Z",
      "products": [
        {
          "@id": "pkg:oci/node@sha256%3A3afbc808e0fe2af41f9183915f19d843c6b7e9ae3aa321f4bd9bbc1145172927?repository_url=cgr.dev%2Fchainguard",
          "identifiers": {
            "purl": "pkg:oci/node@sha256%3A3afbc808e0fe2af41f9183915f19d843c6b7e9ae3aa321f4bd9bbc1145172927?repository_url=cgr.dev%2Fchainguard"
          },
          "subcomponents": [
            {
              "@id": "pkg:apk/wolfi/glibc",
              "identifiers": {
                "purl": "pkg:apk/wolfi/glibc"
              }
            }
          ]
        }
      ],
      "status": "not_affected"
    },

```

## SBOM Compatibility

By default, VEXi will try to discover SBOMs signed and attached to the image using
[sigstore's attestation specification](https://github.com/sigstore/cosign/blob/main/specs/ATTESTATION_SPEC.md). VEXi is compatible with SPDX and CycloneDX. It uses
[protobom](http://github.com/bom-squad/protobom) under the hood to parse and
query SBOM data, which means that VEXi can use any SBOM format supported by 
protobom.
