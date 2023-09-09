package main

func main() {
	tmpFile, err := DownloadSBOM()

	protobom, err := ParseSBOM(tmpFile)

	packages, err := FilterSBOMPackages()

	advisories, err := FindPackageAdvisories()

	vexDocuments, err := GenerateVEXData()

	vexDocument, err := MergeDocuments()

	err := writeVexDocument()
}
