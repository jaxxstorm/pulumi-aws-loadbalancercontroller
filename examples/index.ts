import * as lb from "@jaxxstorm/pulumi-aws-loadbalancercontroller"

const foo = new lb.Awslbcontroller("foo", {
    createNamespace: true,
    namespace: "foo",
})
