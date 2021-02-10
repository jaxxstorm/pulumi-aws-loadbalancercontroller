// *** WARNING: this file was generated by pulumi-gen-awslbcontroller. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

export class Awslbcontroller extends pulumi.ComponentResource {
    /** @internal */
    public static readonly __pulumiType = 'awslbcontroller:index:awslbcontroller';

    /**
     * Returns true if the given object is an instance of Awslbcontroller.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Awslbcontroller {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Awslbcontroller.__pulumiType;
    }


    /**
     * Create a Awslbcontroller resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: AwslbcontrollerArgs, opts?: pulumi.ComponentResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (!(opts && opts.id)) {
            inputs["createNamespace"] = args ? args.createNamespace : undefined;
            inputs["namespace"] = args ? args.namespace : undefined;
        } else {
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(Awslbcontroller.__pulumiType, name, inputs, opts, true /*remote*/);
    }
}

/**
 * The set of arguments for constructing a Awslbcontroller resource.
 */
export interface AwslbcontrollerArgs {
    /**
     * Specifies whether you'd like to create a new namespace to install
     */
    readonly createNamespace?: pulumi.Input<boolean>;
    /**
     * Specifies the namespace to install your resources in
     */
    readonly namespace?: pulumi.Input<string>;
}
