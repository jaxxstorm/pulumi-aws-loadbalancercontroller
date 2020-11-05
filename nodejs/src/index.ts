import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi"
import * as k8s from "@pulumi/kubernetes"
import * as tls from "@pulumi/tls"

export interface AWSLoadBalancerControllerArgs {
    namespace: {
        name: string;
    }
    cluster: {
        name: string
    }
    ingress?: {
        class?: string
    }
    installCRD: boolean
    app?: {
        version?: string
        image?: string
    }
}

export class AWSLoadBalancerController extends pulumi.ComponentResource {
    policy: aws.iam.Policy;
    role: aws.iam.Role;
    chart: k8s.helm.v3.Chart;
    namespace: k8s.core.v1.Namespace;

    // k8s
    serviceAccount: k8s.core.v1.ServiceAccount;
    tlsSecret: k8s.core.v1.Secret;
    clusterRole: k8s.rbac.v1.ClusterRole;
    clusterRoleBinding: k8s.rbac.v1.ClusterRoleBinding;
    kubernetesRole: k8s.rbac.v1.Role;
    roleBinding: k8s.rbac.v1.RoleBinding;
    webhookService: k8s.core.v1.Service;
    validatingWebhook: k8s.admissionregistration.v1.ValidatingWebhookConfiguration;
    deployment: k8s.apps.v1.Deployment;
    mutatingWebhook: k8s.admissionregistration.v1.MutatingWebhookConfiguration;
    caKey: tls.PrivateKey;
    caCert: tls.SelfSignedCert;
    certKey: tls.PrivateKey;
    certRequest: tls.CertRequest;
    cert: tls.LocallySignedCert;

    ingressClass: string = "alb";
    version: string = "v2.0.0";
    image: string = "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller";
    installCRD: boolean = true;

    constructor(name: string, args: AWSLoadBalancerControllerArgs, opts?: pulumi.ComponentResourceOptions) {
        super("jaxxstorm:aws:loadbalancercontroller", name, {}, opts);

        const awsConfig = new pulumi.Config("aws")
        const config = new pulumi.Config()
        const region = awsConfig.require("region")
        const oidcArn = config.require("oidcArn")
        const oidcUrl = config.require("oidcUrl")


        const oidcUrlwithSub = `${oidcUrl}:sub`
        const serviceAccountName = `system:serviceaccount:${args.namespace.name}:${name}-serviceaccount`

        this.ingressClass = (args.ingress?.class ?? "alb")
        this.installCRD = (args.installCRD ?? true)
        this.version = (args.app?.version ?? "v2.0.0")
        this.image = (args.app?.image ?? "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller")

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


        // the role that can be used for the Kubernetes workload
        this.role = new aws.iam.Role(`${name}-role`, {
            assumeRolePolicy: JSON.stringify(policyData)
        }, { parent: this })

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


        // Create a certificate for the webhook
        this.caKey = new tls.PrivateKey(`${name}-ca-privatekey`, {
            algorithm: "RSA",
            ecdsaCurve: "P256",
            rsaBits: 2048,
        }, { parent: this } )

        this.caCert = new tls.SelfSignedCert(`${name}-ca-cert`, {
            keyAlgorithm: this.caKey.algorithm,
            privateKeyPem: this.caKey.privateKeyPem,
            isCaCertificate: true,
            validityPeriodHours: 88600,
            allowedUses: [
                "cert_signing",
                "key_encipherment",
                "digital_signature",
            ],
            subjects: [{
                commonName: `${name}-aws-load-balancer-controller`,
            }]
        }, { parent: this.caKey } )

        this.namespace = new k8s.core.v1.Namespace(`${name}-namespace`, {
            metadata: {
                name: args.namespace.name,
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                }
            }
        }, { parent: this })

        this.serviceAccount = new k8s.core.v1.ServiceAccount(`${name}-serviceAccount`, {
            metadata: {
                name: `${name}-serviceaccount`,
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,

                },
                annotations: {
                    "eks.amazonaws.com/role-arn": this.role.arn.apply(arn => arn),
                },
                namespace: args.namespace.name,
            },
        }, { parent: this.namespace });

        this.clusterRole = new k8s.rbac.v1.ClusterRole(`${name}-clusterrole`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
            },
            rules: [
                {
                    apiGroups: ["elbv2.k8s.aws"],
                    resources: ["targetgroupbindings"],
                    verbs: [
                        "create",
                        "delete",
                        "get",
                        "list",
                        "patch",
                        "update",
                        "watch",
                    ],
                },
                {
                    apiGroups: [""],
                    resources: ["events"],
                    verbs: [
                        "create",
                        "patch",
                    ],
                },
                {
                    apiGroups: [""],
                    resources: ["pods"],
                    verbs: [
                        "get",
                        "list",
                        "watch",
                    ],
                },
                {
                    apiGroups: [
                        "",
                        "extensions",
                        "networking.k8s.io",
                    ],
                    resources: [
                        "services",
                        "ingresses",
                    ],
                    verbs: [
                        "get",
                        "list",
                        "patch",
                        "update",
                        "watch",
                    ],
                },
                {
                    apiGroups: [""],
                    resources: [
                        "nodes",
                        "secrets",
                        "namespaces",
                        "endpoints",
                    ],
                    verbs: [
                        "get",
                        "list",
                        "watch",
                    ],
                },
                {
                    apiGroups: [
                        "elbv2.k8s.aws",
                        "",
                        "extensions",
                        "networking.k8s.io",
                    ],
                    resources: [
                        "targetgroupbindings/status",
                        "pods/status",
                        "services/status",
                        "ingresses/status",
                    ],
                    verbs: [
                        "update",
                        "patch",
                    ],
                },
            ],
        }, { parent: this });
        this.clusterRoleBinding = new k8s.rbac.v1.ClusterRoleBinding(`${name}-clusterrolebinding`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
            },
            roleRef: {
                apiGroup: "rbac.authorization.k8s.io",
                kind: "ClusterRole",
                name: this.clusterRole.metadata.name,
            },
            subjects: [{
                kind: "ServiceAccount",
                name: this.serviceAccount.metadata.name,
                namespace: args.namespace.name,
            }],
        }, { parent: this.namespace });

        this.kubernetesRole = new k8s.rbac.v1.Role(`${name}-role`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
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
        }, { parent: this.namespace });

        this.roleBinding = new k8s.rbac.v1.RoleBinding(`${name}-rolebinding`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
            },
            roleRef: {
                apiGroup: "rbac.authorization.k8s.io",
                kind: "Role",
                name: this.kubernetesRole.metadata.name,
            },
            subjects: [{
                kind: "ServiceAccount",
                name: this.serviceAccount.metadata.name,
                namespace: args.namespace.name,
            }],
        }, { parent: this.kubernetesRole } );

        this.webhookService = new k8s.core.v1.Service(`${name}-webhook-service`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
                annotations: {
                    "pulumi.com/skipAwait": "true",
                }
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
        }, { parent: this.namespace });

        this.certKey = new tls.PrivateKey(`${name}-cert-privatekey`, {
            algorithm: "RSA",
            ecdsaCurve: "P256",
            rsaBits: 2048,
        }, { parent: this })

        this.certRequest = new tls.CertRequest(`${name}-cert-request`, {
            keyAlgorithm: "RSA",
            privateKeyPem: this.certKey.privateKeyPem,
            dnsNames: [
                this.webhookService.metadata.name.apply(name => `${name}.${args.namespace.name}`),
                this.webhookService.metadata.name.apply(name => `${name}.${args.namespace.name}.svc`)
            ],
            subjects: [{
                commonName: this.webhookService.metadata.name
            }]
        }, { parent: this.certKey })

        this.cert = new tls.LocallySignedCert(`${name}-cert`, {
            certRequestPem: this.certRequest.certRequestPem,
            caKeyAlgorithm: this.caKey.algorithm,
            caPrivateKeyPem: this.caKey.privateKeyPem,
            caCertPem: this.caCert.certPem,
            validityPeriodHours: 88600,
            allowedUses: [
                "key_encipherment",
                "digital_signature",
            ]
        }, { parent: this.certKey })

        this.tlsSecret = new k8s.core.v1.Secret(`${name}-tls-secret`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
            },
            type: "kubernetes.io/tls",
            stringData: {
                "ca.crt": this.caCert.certPem,
                "tls.crt": this.cert.certPem,
                "tls.key": this.certKey.privateKeyPem,
            },

        }, { parent: this.namespace, dependsOn: [this.certKey, this.cert, this.certRequest ] });

        let deploymentArgs = [
            `--cluster-name=${args.cluster.name}`,
            `--ingress-class=${this.ingressClass}`,
            `--aws-region=${region}`
        ]

        this.deployment = new k8s.apps.v1.Deployment(`${name}-controller-deployment`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
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
                                secretName: this.tlsSecret.metadata.name,
                            },
                        }],
                        securityContext: {
                            fsGroup: 65534,
                        },
                        containers: [{
                            name: "aws-load-balancer-controller",
                            args: deploymentArgs,
                            command: ["/controller"],
                            securityContext: {
                                allowPrivilegeEscalation: false,
                                readOnlyRootFilesystem: true,
                                runAsNonRoot: true,
                            },
                            image: `${this.image}:${this.version}`,
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
        }, { parent: this.namespace });

        this.mutatingWebhook = new k8s.admissionregistration.v1.MutatingWebhookConfiguration(`${name}-mutating-webhook`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
            },
            webhooks: [
                {
                    clientConfig: {
                        caBundle: this.caCert.certPem.apply(pem => Buffer.from(pem).toString("base64")),
                        service: {
                            name: this.webhookService.metadata.name,
                            namespace: args.namespace.name,
                            path: "/mutate-v1-pod",
                        },
                    },
                    failurePolicy: "Fail",
                    name: "mpod.elbv2.k8s.aws",
                    admissionReviewVersions: ["v1beta1"],
                    namespaceSelector: {
                        matchExpressions: [{
                            key: "elbv2.k8s.aws/pod-readiness-gate-inject",
                            operator: "In",
                            values: ["enabled"],
                        }],
                    },
                    rules: [{
                        apiGroups: [""],
                        apiVersions: ["v1"],
                        operations: ["CREATE"],
                        resources: ["pods"],
                    }],
                    sideEffects: "None",
                },
                {
                    clientConfig: {
                        caBundle: this.caCert.certPem.apply(pem => Buffer.from(pem).toString("base64")),
                        service: {
                            name: this.webhookService.metadata.name,
                            namespace: args.namespace.name,
                            path: "/mutate-elbv2-k8s-aws-v1beta1-targetgroupbinding",
                        },
                    },
                    failurePolicy: "Fail",
                    name: "mtargetgroupbinding.elbv2.k8s.aws",
                    admissionReviewVersions: ["v1beta1"],
                    rules: [{
                        apiGroups: ["elbv2.k8s.aws"],
                        apiVersions: ["v1beta1"],
                        operations: [
                            "CREATE",
                            "UPDATE",
                        ],
                        resources: ["targetgroupbindings"],
                    }],
                    sideEffects: "None",
                },
            ],
        }, { parent: this });
        this.validatingWebhook = new k8s.admissionregistration.v1.ValidatingWebhookConfiguration(`${name}-validating-webhook`, {
            metadata: {
                labels: {
                    "app.kubernetes.io/name": "aws-load-balancer-controller",
                    "app.kubernetes.io/instance": name,
                },
                namespace: args.namespace.name,
            },
            webhooks: [{
                clientConfig: {
                    caBundle: this.caCert.certPem.apply(pem => Buffer.from(pem).toString("base64")),
                    service: {
                        name: this.webhookService.metadata.name,
                        namespace: args.namespace.name,
                        path: "/validate-elbv2-k8s-aws-v1beta1-targetgroupbinding",
                    },
                },
                failurePolicy: "Fail",
                name: "vtargetgroupbinding.elbv2.k8s.aws",
                admissionReviewVersions: ["v1beta1"],
                rules: [{
                    apiGroups: ["elbv2.k8s.aws"],
                    apiVersions: ["v1beta1"],
                    operations: [
                        "CREATE",
                        "UPDATE",
                    ],
                    resources: ["targetgroupbindings"],
                }],
                sideEffects: "None",
            }],
        }, { parent: this });

        if (this.installCRD) {
            new k8s.yaml.ConfigFile(`${name}-crd`, {
                file: "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/6ed50eba295fc76467cb2d31d2ad0661463d96ce/config/crd/bases/elbv2.k8s.aws_targetgroupbindings.yaml",
            }, { parent: this })
        }

        this.registerOutputs({});
    }
}
