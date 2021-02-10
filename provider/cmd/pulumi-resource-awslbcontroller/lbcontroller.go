// Copyright 2016-2021, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v2/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v2/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LBController struct {
	pulumi.ResourceState

	ID pulumi.IDOutput
	Namespace *corev1.Namespace
}

func NewLBController(ctx *pulumi.Context,
	name string, args *LBControllerArgs, opts ...pulumi.ResourceOption) (*LBController, error) {
	if args == nil {
		args = &LBControllerArgs{}
	}

	component := &LBController{}
	err := ctx.RegisterComponentResource("awslbcontroller:index:awslbcontroller", name, component, opts...)
	if err != nil {
		return nil, err
	}

	createNamespace := args.CreateNamespace

	namespace := args.Namespace
	if namespace == nil {
		namespace = pulumi.String("kube-system")
	}

	if createNamespace {
		component.Namespace, err = corev1.NewNamespace(ctx, name, &corev1.NamespaceArgs{
			Metadata: &metav1.ObjectMetaArgs{
				Name: args.Namespace,
			},
		}, pulumi.Parent(component))
		if err != nil {
			return nil, err
		}
	}

	/*
	FIXME:
	from the example component, this happens
	component.ID = component.Vpc.ID()
	why? How do i convert this into this situation?
	*/

	err = ctx.RegisterResourceOutputs(component, pulumi.Map{
		"namespaceName": component.Namespace.Metadata.Name(), // this currently seems to panic, so I'm not setting this correctly
	})
	if err != nil {
		return nil, err
	}

	return component, nil
}

// The set of arguments for constructing a LBController component.
type LBControllerArgs struct {
	CreateNamespace bool
	Namespace       pulumi.StringInput `pulumi:"namespace"`
}
