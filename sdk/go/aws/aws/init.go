// *** WARNING: this file was generated by pulumi-gen-lbcontroller. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package aws

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/jaxxstorm/pulumi-aws-loadbalancercontroller/sdk/go/vpc"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "jaxxstorm:aws:loadbalancercontroller":
		r, err = NewLoadbalancercontroller(ctx, name, nil, pulumi.URN_(urn))
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	return
}

func init() {
	version, err := vpc.PkgVersion()
	if err != nil {
		fmt.Println("failed to determine package version. defaulting to v1: %v", err)
	}
	pulumi.RegisterResourceModule(
		"aws-loadbalancercontroller",
		"aws",
		&module{version},
	)
}
