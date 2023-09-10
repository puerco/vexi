package convert

import (
	"github.com/openvex/go-vex/pkg/vex"
	v2 "github.com/wolfi-dev/wolfictl/pkg/configs/advisory/v2"
)

// This package contains functions to convert data from advisories to VEX

// EventToVEXStatus converts an advisory event type to the corresponding
// vex status. Note that EventTypeAnalysisNotPlanned and EventTypeFixNotPlanned
// don't have good equivalentes in VEX so those event types will return an
// empty status.
func EventToVEXStatus(evt v2.Event) vex.Status {
	switch evt.Type {
	case v2.EventTypeFixed:
		return vex.StatusFixed

	case v2.EventTypeDetection:
		return vex.StatusUnderInvestigation

	case v2.EventTypeTruePositiveDetermination:
		return vex.StatusAffected

	case v2.EventTypeFalsePositiveDetermination:
		return vex.StatusNotAffected

		// case v2.EventTypeAnalysisNotPlanned:
	// case v2.EventTypeFixNotPlanned:

	default:
		return ""
	}
}
