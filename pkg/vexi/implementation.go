package vexi

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/puerco/deployer/pkg/deploy"
	"github.com/puerco/deployer/pkg/payload"
	"github.com/puerco/vexi/pkg/convert"
	"github.com/puerco/vexi/pkg/vexi/options"
	"github.com/sirupsen/logrus"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
	rwos "github.com/wolfi-dev/wolfictl/pkg/configs/rwfs/os"
	"sigs.k8s.io/release-sdk/git"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/openvex/go-vex/pkg/vex"
)

type generatorImplementation interface {
	ValidateOptions(*options.Options) error
	CloneAdvisoryRepo(options.Options) error
	DownloadSBOM(options.Options, string) ([]*payload.Document, error)
	ParseSBOM(*payload.Document) (*sbom.Document, error)
	FilterSBOMPackages(*sbom.Document) (*sbom.NodeList, error)
	FindPackageAdvisories(options.Options, *sbom.NodeList) ([]v2.Document, error)
	GenerateVEXData(options.Options, []v2.Document) ([]*vex.VEX, error)
	MergeDocuments([]*vex.VEX) (*vex.VEX, error)
	WriteVexDocument(options.Options, *vex.VEX) error
}

type defaultVexiImplementation struct{}

// ValidateOptions calls the options validation function.
func (dvi *defaultVexiImplementation) ValidateOptions(opts *options.Options) error {
	return opts.Validate()
}

// CloneAdvisoryRepo clones the advisories repository
func (dvi *defaultVexiImplementation) CloneAdvisoryRepo(opts options.Options) error {
	if _, err := git.CloneOrOpenGitHubRepo(
		opts.AdvisoriesDir, opts.RepoOrg, opts.RepoName, false,
	); err != nil {
		return fmt.Errorf(
			"cloning repository %s/%s to %s: %w",
			opts.RepoOrg, opts.RepoName, opts.AdvisoriesDir, err,
		)
	}
	return nil
}

// DownloadSBOM retrieves all the SBOMs associated with the image.
func (dvi *defaultVexiImplementation) DownloadSBOM(opts options.Options, imageRef string) ([]*payload.Document, error) {
	// Use the mighty deployer to drop any SBOMs from the image to vexi
	probe := deploy.NewProbe()

	probe.Options.Formats = opts.PredicateTypesList

	docs, err := probe.Fetch(opts.ImagePurl)
	if err != nil {
		fmt.Fprintf(os.Stdout, "fetching documents: %s\n", err)
		os.Exit(1)
	}

	logrus.Infof("Downloaded %d SBOMs from image %s", len(docs), imageRef)

	return docs, nil
}

// ParseSBOM takes a document discovered by deployer, detects the format and
// returns a protobom with the parsed data.
func (dvi *defaultVexiImplementation) ParseSBOM(payloadDoc *payload.Document) (*sbom.Document, error) {
	r := reader.New()
	bom, err := r.ParseStream(payloadDoc)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	return bom, nil
}

func (dvi *defaultVexiImplementation) FilterSBOMPackages(bom *sbom.Document) (*sbom.NodeList, error) {
	// Fetch all apk nodes from the SBOM
	nodelist := bom.NodeList.GetNodesByPurlType("apk")

	// Assemble a list of all non-wolfi apks
	list := []string{}
	for _, n := range nodelist.Nodes {
		if !strings.HasPrefix(string(n.Purl()), "pkg:apk/wolfi/") {
			list = append(list, n.Id)
		}
	}

	// Remove the nodes
	nodelist.RemoveNodes(list)

	// Return the nodelist
	return nodelist, nil
}

func (dvi *defaultVexiImplementation) FindPackageAdvisories(opts options.Options, nodelist *sbom.NodeList) ([]v2.Document, error) {
	advisoriesFsys := rwos.DirFS(opts.AdvisoriesDir)
	advisoryCfgs, err := v2.NewIndex(advisoriesFsys)
	if err != nil {
		return nil, err
	}

	var cfgs []v2.Document
	for _, node := range nodelist.Nodes {
		cfgs = append(cfgs, advisoryCfgs.Select().WhereName(node.Name).Configurations()...)
	}
	return cfgs, nil
}

// GenerateVEXData reads the avisroy data and transforms it into OpenVEX
func (dvi *defaultVexiImplementation) GenerateVEXData(opts options.Options, documents []v2.Document) ([]*vex.VEX, error) {
	vexDocuments := []*vex.VEX{}
	vexDoc := vex.New()
	for _, d := range documents {
		for _, adv := range d.Advisories {
			if len(adv.Events) == 0 {
				continue
			}

			// Cycle the advisory events
			sorted := adv.SortedEvents()
			for _, evt := range sorted {
				// Get the vex status. We only handle the event types that
				// correspond to VEX statuses
				status := convert.EventToVEXStatus(evt)
				if status == "" {
					logrus.Debugf("Skiping event of type %s", evt.Type)
					continue
				}

				t := time.Time(evt.Timestamp)
				packagePurl := fmt.Sprintf("pkg:apk/wolfi/%s", d.Package.Name)

				vexStatement := vex.Statement{
					Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(adv.ID)},
					Timestamp:     &t,
					Products: []vex.Product{
						{
							Component: vex.Component{
								ID: opts.ImagePurl,
								Identifiers: map[vex.IdentifierType]string{
									vex.PURL: opts.ImagePurl,
								},
							},
							Subcomponents: []vex.Subcomponent{
								{
									Component: vex.Component{
										ID: packagePurl,
										Identifiers: map[vex.IdentifierType]string{
											vex.PURL: packagePurl,
										},
									},
								},
							},
						},
					},
					Status:          status,
					StatusNotes:     "",
					Justification:   "",
					ImpactStatement: "",
					//ActionStatement: "",
				}

				vexDoc.Statements = append(vexDoc.Statements, vexStatement)
			}
		}
		vexDocuments = append(vexDocuments, &vexDoc)
	}
	return vexDocuments, nil
}

// MergeDocuments combines the documents generated from the packages into a single one.
func (dvi *defaultVexiImplementation) MergeDocuments(vexDocuments []*vex.VEX) (*vex.VEX, error) {
	doc, err := vex.MergeDocuments(vexDocuments)
	if err != nil {
		return nil, fmt.Errorf("merging vex data: %w", err)
	}
	return doc, nil
}

// WriteVexDocument dumps the vex data to the user specified file or STDOUT.
func (dvi *defaultVexiImplementation) WriteVexDocument(opts options.Options, doc *vex.VEX) (err error) {
	f := os.Stdout
	if opts.OutFile != "" {
		f, err = os.Create(opts.OutFile)
		if err != nil {
			return fmt.Errorf("opening file for writing: %w", err)
		}
	}
	if err := doc.ToJSON(f); err != nil {
		return fmt.Errorf("rendering JSON to file %w", err)
	}
	return nil
}
