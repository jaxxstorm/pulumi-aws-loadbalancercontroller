import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi"
import * as k8s from "@pulumi/kubernetes"

export interface AWSLoadBalancerControllerArgs {
    namespace: {
        create: boolean;
        name: string;
    }
    cluster: {
        name: string
    }
    ingress?: {
        class?: string
    }
    vpc: {
        id: string
    }
}

export class AWSLoadBalancerController extends pulumi.ComponentResource {
    policy: aws.iam.Policy;
    role: aws.iam.Role;
    chart: k8s.helm.v3.Chart;
    namespace: k8s.core.v1.Namespace;
    ingressClass: string = "alb";

    constructor(name: string, args: AWSLoadBalancerControllerArgs, opts?: pulumi.ComponentResourceOptions) {
        super("jaxxstorm:aws:loadbalancercontroller", name, {}, opts);

        const awsConfig = new pulumi.Config("aws")
        const config = new pulumi.Config()
        const region = awsConfig.require("region")
        const oidcArn = config.require("oidcArn")
        const oidcUrl = config.require("oidcUrl")


        const oidcUrlwithSub = `${oidcUrl}:sub`
        const serviceAccountName = `system:serviceaccount:${args.namespace.name}:${name}-aws-load-balancer-controller-sa`

        const policyData = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": oidcArn,
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        [oidcUrlwithSub]: serviceAccountName,
                    }
                }
            }]
        }

        this.ingressClass = (args.ingress?.class ?? "alb")

        // the role that can be used for the Kubernetes workload
        this.role = new aws.iam.Role(`${name}-role`, {
            assumeRolePolicy: JSON.stringify(policyData)

        })

        // The IAM policy need for the controller to operate correctly
        this.policy = new aws.iam.Policy(`${name}-policy`, {
            policy: JSON.stringify({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateServiceLinkedRole",
                        "ec2:DescribeAccountAttributes",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeInstances",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeTags",
                        "elasticloadbalancing:DescribeLoadBalancers",
                        "elasticloadbalancing:DescribeLoadBalancerAttributes",
                        "elasticloadbalancing:DescribeListeners",
                        "elasticloadbalancing:DescribeListenerCertificates",
                        "elasticloadbalancing:DescribeSSLPolicies",
                        "elasticloadbalancing:DescribeRules",
                        "elasticloadbalancing:DescribeTargetGroups",
                        "elasticloadbalancing:DescribeTargetGroupAttributes",
                        "elasticloadbalancing:DescribeTargetHealth",
                        "elasticloadbalancing:DescribeTags",

                    ],
                    "Resource": "*",
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "cognito-idp:DescribeUserPoolClient",
                        "acm:ListCertificates",
                        "acm:DescribeCertificate",
                        "iam:ListServerCertificates",
                        "iam:GetServerCertificate",
                        "waf-regional:GetWebACL",
                        "waf-regional:GetWebACLForResource",
                        "waf-regional:AssociateWebACL",
                        "waf-regional:DisassociateWebACL",
                        "wafv2:GetWebACL",
                        "wafv2:GetWebACLForResource",
                        "wafv2:AssociateWebACL",
                        "wafv2:DisassociateWebACL",
                        "shield:GetSubscriptionState",
                        "shield:DescribeProtection",
                        "shield:CreateProtection",
                        "shield:DeleteProtection"
                    ],
                    "Resource": "*"
                },{
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress"
                    ],
                    "Resource": "*",
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateSecurityGroup"
                    ],
                    "Resource": "*",
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateTags"
                    ],
                    "Resource": "arn:aws:ec2:*:*:security-group/*",
                    "Condition": {
                        "StringEquals": {
                            "ec2:CreateAction": "CreateSecurityGroup"
                        },
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "false",
                        }
                    }
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateTags",
                        "ec2:DeleteTags"
                    ],
                    "Resource": "arn:aws:ec2:*:*:security-group/*",
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    }
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:DeleteSecurityGroup"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    }
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:CreateLoadBalancer",
                        "elasticloadbalancing:CreateTargetGroup"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                        }
                    }
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:CreateListener",
                        "elasticloadbalancing:DeleteListener",
                        "elasticloadbalancing:CreateRule",
                        "elasticloadbalancing:DeleteRule"
                    ],
                    "Resource": "*"
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:AddTags",
                        "elasticloadbalancing:RemoveTags"
                    ],
                    "Resource": [
                        "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    }
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:ModifyLoadBalancerAttributes",
                        "elasticloadbalancing:SetIpAddressType",
                        "elasticloadbalancing:SetSecurityGroups",
                        "elasticloadbalancing:SetSubnets",
                        "elasticloadbalancing:DeleteLoadBalancer",
                        "elasticloadbalancing:ModifyTargetGroup",
                        "elasticloadbalancing:ModifyTargetGroupAttributes",
                        "elasticloadbalancing:RegisterTargets",
                        "elasticloadbalancing:DeregisterTargets",
                        "elasticloadbalancing:DeleteTargetGroup"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    }
                }, {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:SetWebAcl",
                        "elasticloadbalancing:ModifyListener",
                        "elasticloadbalancing:AddListenerCertificates",
                        "elasticloadbalancing:RemoveListenerCertificates",
                        "elasticloadbalancing:ModifyRule"
                    ],
                    "Resource": "*"
                }]
            })
        }, { parent: this.role });

        // Attach the role to the policy
        new aws.iam.PolicyAttachment(`${name}-policy-attachment`, {
            policyArn: this.policy.arn,
            roles: [ this.role.name ]
        }, { parent: this.policy } )

        if (args.namespace.create) {
            this.namespace = new k8s.core.v1.Namespace(`${name}-namespace`, {
                metadata: {
                    name: args.namespace.name,
                    labels: {
                        "app.kubernetes.io/name": "aws-load-balancer-controller",
                        "app.kubernetes.io/instance": name,
                        "app.kubernetes.io/version": "v2.0.0",
                    }
                }
            })
        }

       this.chart = new k8s.helm.v3.Chart(`${name}-chart`, {
           namespace: args.namespace.name,
           chart: "aws-load-balancer-controller",
           fetchOpts: { repo: "https://aws.github.io/eks-charts" },
           values: {
               serviceAccount: {
                   create: true,
                   name: `${name}-aws-load-balancer-controller-sa`,
                   annotations: {
                       "eks.amazonaws.com/role-arn": this.role.arn.apply(arn => arn)
                   }
               },
               clusterName: args.cluster.name,
               region: region,
           }

       })




        this.registerOutputs({});
    }
}
