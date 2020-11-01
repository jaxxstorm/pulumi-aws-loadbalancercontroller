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
}

export class AWSLoadBalancerController extends pulumi.ComponentResource {
    policy: aws.iam.Policy;
    role: aws.iam.Role;
    serviceAccount: k8s.core.v1.ServiceAccount;
    namespace: k8s.core.v1.Namespace;
    kubernetesRole: k8s.rbac.v1.Role;
    roleBinding: k8s.rbac.v1.RoleBinding;
    service: k8s.core.v1.Service;
    deployment: k8s.apps.v1.Deployment;
    ingressClass: string = "alb";

    constructor(name: string, args: AWSLoadBalancerControllerArgs, opts?: pulumi.ComponentResourceOptions) {
        super("jaxxstorm:aws:loadbalancercontroller", name, {}, opts);

        const awsConfig = new pulumi.Config("aws")
        const config = new pulumi.Config()
        const region = awsConfig.require("region")
        const oidcArn = config.require("oidcArn")
        const oidcUrl = config.require("oidcUrl")


        const oidcUrlwithSub = `${oidcUrl}:sub`
        const serviceAccountName = `system:serviceaccount:${args.namespace.name}:aws-load-balancer-controller`

        this.ingressClass = (args.ingress?.class ?? "alb")

        // the role that can be used for the Kubernetes workload
        this.role = new aws.iam.Role(`${name}-role`, {
            assumeRolePolicy: JSON.stringify({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": oidcArn,
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            oidcUrlwithSub: serviceAccountName,
                        }
                    }
                }]
            })

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

        this.serviceAccount = new k8s.core.v1.ServiceAccount(`${name}-serviceaccount`, {
            metadata: {
                namespace: args.namespace.name,
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                    "app.kubernetes.io/version": "v2.0.0",
                }
            }
        })

        this.kubernetesRole = new k8s.rbac.v1.Role(`${name}-role`, {
            metadata: {
                namespace: args.namespace.name,
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                    "app.kubernetes.io/version": "v2.0.0",
                }
            },
            rules: [
                {
                    apiGroups: [""],
                    resources: ["configmaps"],
                    verbs: ["create"],
                },
                {
                    apiGroups: [""],
                    resources: ["configmaps"],
                    resourceNames: ["aws-load-balancer-controller-leader"],
                    verbs: [
                        "get",
                        "patch",
                        "update",
                    ],
                },
            ],
        });

        this.roleBinding = new k8s.rbac.v1.RoleBinding(`${name}-rolebinding`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                    "app.kubernetes.io/version": "v2.0.0",
                }
            },
            roleRef: {
                apiGroup: "rbac.authorization.k8s.io",
                kind: "Role",
                name: `${name}-aws-load-balancer-controller-leader-election-role`,
            },
            subjects: [{
                kind: "ServiceAccount",
                name: `${name}-aws-load-balancer-controller`,
                namespace: args.namespace.name,
            }],
        }, { parent: this.role });

        this.service = new k8s.core.v1.Service(`${name}-service`, {
            metadata: {
                name: "aws-load-balancer-webhook-service",
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                    "app.kubernetes.io/version": "v2.0.0",
                },
            },
            spec: {
                ports: [{
                    port: 443,
                    targetPort: 9443,
                }],
                selector: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
            },
        });

        this.deployment = new k8s.apps.v1.Deployment(`${name}-deployment`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                    "app.kubernetes.io/version": "v2.0.0",
                },
            },
            spec: {
                replicas: 1,
                selector: {
                    matchLabels: {
                        "app.kubernetes.io/name": "aws-load-balancer-controller",
                        "app.kubernetes.io/instance": name,
                    },
                },
                template: {
                    metadata: {
                        labels: {
                            "app.kubernetes.io/name": "aws-load-balancer-controller",
                            "app.kubernetes.io/instance": name,
                        },
                        annotations: {
                            "prometheus.io/scrape": "true",
                            "prometheus.io/port": "8080",
                        },
                    },
                    spec: {
                        serviceAccountName: this.serviceAccount.metadata.name,
                        volumes: [{
                            name: "cert",
                            secret: {
                                defaultMode: 420,
                                secretName: "aws-load-balancer-tls",
                            },
                        }],
                        securityContext: {
                            fsGroup: 65534,
                        },
                        containers: [{
                            name: "aws-load-balancer-controller",
                            args: [
                                `--cluster-name=${args.cluster.name}`,
                                `--ingress-class=${this.ingressClass}`,
                            ],
                            command: ["/controller"],
                            securityContext: {
                                allowPrivilegeEscalation: false,
                                readOnlyRootFilesystem: true,
                                runAsNonRoot: true,
                            },
                            image: "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller:v2.0.0",
                            imagePullPolicy: "IfNotPresent",
                            volumeMounts: [{
                                mountPath: "/tmp/k8s-webhook-server/serving-certs",
                                name: "cert",
                                readOnly: true,
                            }],
                            ports: [
                                {
                                    name: "webhook-server",
                                    containerPort: 9443,
                                    protocol: "TCP",
                                },
                                {
                                    name: "metrics-server",
                                    containerPort: 8080,
                                    protocol: "TCP",
                                },
                            ],
                            resources: {},
                            livenessProbe: {
                                failureThreshold: 2,
                                httpGet: {
                                    path: "/healthz",
                                    port: 61779,
                                    scheme: "HTTP",
                                },
                                initialDelaySeconds: 30,
                                timeoutSeconds: 10,
                            },
                        }],
                        terminationGracePeriodSeconds: 10,
                    },
                },
            },
        });




        this.registerOutputs({});
    }
}
