// *** WARNING: this file was generated by pulumi-gen-awslbcontroller. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

// Export members:
export * from "./awslbcontroller";
export * from "./provider";

// Import resources to register:
import { Awslbcontroller } from "./awslbcontroller";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "awslbcontroller:index:awslbcontroller":
                return new Awslbcontroller(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("awslbcontroller", "index", _module)

import { Provider } from "./provider";

pulumi.runtime.registerResourcePackage("awslbcontroller", {
    version: utilities.getVersion(),
    constructProvider: (name: string, type: string, urn: string): pulumi.ProviderResource => {
        if (type !== "pulumi:providers:awslbcontroller") {
            throw new Error(`unknown provider type ${type}`);
        }
        return new Provider(name, <any>undefined, { urn });
    },
});