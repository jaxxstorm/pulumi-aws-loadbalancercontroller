// *** WARNING: this file was generated by pulumi-gen-awslbcontroller. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Awslbcontroller
{
    [AwslbcontrollerResourceType("awslbcontroller:index:awslbcontroller")]
    public partial class Awslbcontroller : Pulumi.ComponentResource
    {
        /// <summary>
        /// Create a Awslbcontroller resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Awslbcontroller(string name, AwslbcontrollerArgs? args = null, ComponentResourceOptions? options = null)
            : base("awslbcontroller:index:awslbcontroller", name, args ?? new AwslbcontrollerArgs(), MakeResourceOptions(options, ""), remote: true)
        {
        }

        private static ComponentResourceOptions MakeResourceOptions(ComponentResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new ComponentResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = ComponentResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class AwslbcontrollerArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Specifies whether you'd like to create a new namespace to install
        /// </summary>
        [Input("createNamespace")]
        public Input<bool>? CreateNamespace { get; set; }

        /// <summary>
        /// Specifies the namespace to install your resources in
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        public AwslbcontrollerArgs()
        {
        }
    }
}
