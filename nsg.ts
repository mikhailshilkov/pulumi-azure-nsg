import * as pulumi from "@pulumi/pulumi";
import * as azure from "@pulumi/azure-native/network";

// Type definitions for the component inputs
export interface NetworkSecurityGroupArgs {
    /** Name of the resource group */
    resourceGroupName: pulumi.Input<string>;
    
    /** Network security group name */
    securityGroupName?: pulumi.Input<string>;
    
    /** Location (Azure Region) for the network security group */
    location?: pulumi.Input<string>;
    
    /** Security rules for the network security group */
    customRules?: SecurityRule[];
    
    /** Predefined rules */
    predefinedRules?: PredefinedRule[];
    
    /** Source address prefix to be applied to all predefined rules. 
     * list(string) only allowed one element (CIDR, `*`, source IP range or Tags). 
     * Example ["10.0.3.0/24"] or ["VirtualNetwork"] */
    sourceAddressPrefix?: pulumi.Input<string[]>;
    
    /** Source address prefixes to be applied to all predefined rules. 
     * Example ["10.0.3.0/32","10.0.3.128/32"] */
    sourceAddressPrefixes?: pulumi.Input<string[]>;
    
    /** Destination address prefix to be applied to all predefined rules. 
     * list(string) only allowed one element (CIDR, `*`, source IP range or Tags). 
     * Example ["10.0.3.0/24"] or ["VirtualNetwork"] */
    destinationAddressPrefix?: pulumi.Input<string[]>;
    
    /** Destination address prefixes to be applied to all predefined rules. 
     * Example ["10.0.3.0/32","10.0.3.128/32"] */
    destinationAddressPrefixes?: pulumi.Input<string[]>;

    /** The tags to associate with your network security group */
    // tags?: pulumi.Input<{[key: string]: string}>;    
}

// Security rule.
export interface SecurityRule {
    /** Name of the security rule */
    name: string;
    
    /** Priority of the security rule. Must be between 100 and 4096 */
    priority: number;
    
    /** Direction of the rule. Possible values are Inbound or Outbound */
    direction?: string;
    
    /** Allow or Deny action */
    access?: string;
    
    /** Network protocol this rule applies to */
    protocol?: string;
    
    /** Source port or range. Integer or range between 0 and 65535 or * */
    sourcePortRange?: string;
    
    /** Destination port or range. Integer or range between 0 and 65535 or * */
    destinationPortRange?: string;
    
    /** CIDR or source IP range or * to match any IP */
    sourceAddressPrefix?: string;
    
    /** List of source address prefixes */
    sourceAddressPrefixes?: string[];
    
    /** CIDR or destination IP range or * to match any IP */
    destinationAddressPrefix?: string;
    
    /** List of destination address prefixes */
    destinationAddressPrefixes?: string[];
    
    /** Description of the rule */
    description?: string;
    
    /** List of source Application Security Group IDs */
    sourceApplicationSecurityGroupIds?: string[];
    
    /** List of destination Application Security Group IDs */
    destinationApplicationSecurityGroupIds?: string[];
}

// Predefined rule.
export interface PredefinedRule {
    /** Name of the predefined rule */
    name: string;
    
    /** Priority of the rule. Must be between 100 and 4096 */
    priority: number;
    
    /** Source port or range. Integer or range between 0 and 65535 or * */
    sourcePortRange?: string;
    
    /** List of source Application Security Group IDs */
    sourceApplicationSecurityGroupIds?: string[];
    
    /** List of destination Application Security Group IDs */
    destinationApplicationSecurityGroupIds?: string[];
}

export class NetworkSecurityGroup extends pulumi.ComponentResource {
    /** The underlying Network Security Group resource */
    public readonly networkSecurityGroup: azure.NetworkSecurityGroup;
    
    /** The id of newly created network security group */
    public readonly networkSecurityGroupId: pulumi.Output<string>;
    
    /** The name of newly created network security group */
    public readonly networkSecurityGroupName: pulumi.Output<string>;

    constructor(name: string, args: NetworkSecurityGroupArgs, opts?: pulumi.ComponentResourceOptions) {
        super("azure-nsg:index:NetworkSecurityGroup", name, args, opts);

        // Create the Network Security Group
        this.networkSecurityGroup = new azure.NetworkSecurityGroup(name, {
            resourceGroupName: args.resourceGroupName,
            location: args.location,
            networkSecurityGroupName: args.securityGroupName || name,
            //tags: args.tags,
            securityRules: [], // We'll add rules separately
        }, { parent: this });

        // Create predefined rules
        if (args.predefinedRules) {
            args.predefinedRules.forEach((rule, index) => {
                const predefinedRule = predefinedRules[rule.name];
                if (!predefinedRule) return;

                const defaultPriority = 4096 - (args.predefinedRules?.length || 0) + index;
                
                const priority = rule.priority ?? defaultPriority;
                validatePriority(priority);
                
                new azure.SecurityRule(`${name}-predefined-${index}`, {
                    resourceGroupName: args.resourceGroupName,
                    networkSecurityGroupName: this.networkSecurityGroup.name,
                    securityRuleName: rule.name,
                    priority: priority,
                    direction: predefinedRule.direction,
                    access: predefinedRule.access,
                    protocol: predefinedRule.protocol,
                    sourcePortRange: (!rule.sourcePortRange || rule.sourcePortRange === "*") ? "*" : 
                        (!rule.sourcePortRange.includes(",") ? rule.sourcePortRange : undefined),
                    sourcePortRanges: (rule.sourcePortRange && rule.sourcePortRange !== "*" && rule.sourcePortRange.includes(",")) ?
                        rule.sourcePortRange.split(",").map(p => p.trim()) : undefined,
                    destinationPortRange: !predefinedRule.destinationPortRange.includes("-") && !predefinedRule.destinationPortRange.includes(",") ? 
                        predefinedRule.destinationPortRange : undefined,
                    destinationPortRanges: (predefinedRule.destinationPortRange.includes("-") || predefinedRule.destinationPortRange.includes(",")) ? 
                        [predefinedRule.destinationPortRange] : undefined,
                    sourceAddressPrefix: args.sourceAddressPrefix ? pulumi.output(args.sourceAddressPrefix).apply(p => p.join(",")) : "*",
                    sourceAddressPrefixes: args.sourceAddressPrefixes,
                    destinationAddressPrefix: args.destinationAddressPrefix ? pulumi.output(args.destinationAddressPrefix).apply(p => p.join(",")) : "*",
                    destinationAddressPrefixes: args.destinationAddressPrefixes,
                    sourceApplicationSecurityGroups: rule.sourceApplicationSecurityGroupIds ? 
                        rule.sourceApplicationSecurityGroupIds.map(id => ({ id })) : undefined,
                    destinationApplicationSecurityGroups: rule.destinationApplicationSecurityGroupIds ? 
                        rule.destinationApplicationSecurityGroupIds.map(id => ({ id })) : undefined,
                    description: predefinedRule.description,
                }, { parent: this.networkSecurityGroup });
            });
        }

        // Create custom rules
        if (args.customRules) {
            args.customRules.forEach((rule, index) => {
                validatePriority(rule.priority);
                
                new azure.SecurityRule(`${name}-custom-${index}`, {
                    resourceGroupName: args.resourceGroupName,
                    networkSecurityGroupName: this.networkSecurityGroup.name,
                    securityRuleName: rule.name,
                    priority: rule.priority,
                    direction: rule.direction || "Inbound",
                    access: rule.access || "Allow",
                    protocol: rule.protocol || "*",
                    sourcePortRange: (!rule.sourcePortRange || rule.sourcePortRange === "*") ? "*" : 
                        (!rule.sourcePortRange.includes(",") ? rule.sourcePortRange : undefined),
                    sourcePortRanges: (rule.sourcePortRange && rule.sourcePortRange !== "*" && rule.sourcePortRange.includes(",")) ?
                        rule.sourcePortRange.split(",").map(p => p.trim()) : undefined,
                    destinationPortRange: rule.destinationPortRange && !rule.destinationPortRange.includes("-") && !rule.destinationPortRange.includes(",") ? 
                        rule.destinationPortRange : undefined,
                    destinationPortRanges: rule.destinationPortRange && (rule.destinationPortRange.includes("-") || rule.destinationPortRange.includes(",")) ? 
                        [rule.destinationPortRange] : undefined,
                    sourceAddressPrefix: rule.sourceAddressPrefix || "*",
                    sourceAddressPrefixes: rule.sourceAddressPrefixes,
                    destinationAddressPrefix: rule.destinationAddressPrefix || "*",
                    destinationAddressPrefixes: rule.destinationAddressPrefixes,
                    sourceApplicationSecurityGroups: rule.sourceApplicationSecurityGroupIds ? 
                        rule.sourceApplicationSecurityGroupIds.map(id => ({ id })) : undefined,
                    destinationApplicationSecurityGroups: rule.destinationApplicationSecurityGroupIds ? 
                        rule.destinationApplicationSecurityGroupIds.map(id => ({ id })) : undefined,
                    description: rule.description || `Security rule for ${rule.name}`,
                }, { parent: this.networkSecurityGroup });
            });
        }

        this.networkSecurityGroupId = this.networkSecurityGroup.id;
        this.networkSecurityGroupName = this.networkSecurityGroup.name;

        this.registerOutputs({
            networkSecurityGroupId: this.networkSecurityGroupId,
            networkSecurityGroupName: this.networkSecurityGroupName,
        });
    }
}


interface PredefinedRuleDefinition {
    direction: string;
    access: string;
    protocol: string;
    sourcePortRange: string;
    destinationPortRange: string;
    description: string;
}

// Predefined rules mapping
const predefinedRules: {[key: string]: PredefinedRuleDefinition} = {
    // ActiveDirectory rules
    "ActiveDirectory-AllowADReplication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourcePortRange: "*",
        destinationPortRange: "389",
        description: "AllowADReplication"
    },
    "ActiveDirectory-AllowADReplicationSSL": {
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourcePortRange: "*",
        destinationPortRange: "636",
        description: "AllowADReplicationSSL"
    },
    "ActiveDirectory-AllowADGCReplication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "3268",
        description: "AllowADGCReplication"
    },
    "ActiveDirectory-AllowADGCReplicationSSL": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "3269",
        description: "AllowADGCReplicationSSL"
    },
    "ActiveDirectory-AllowDNS": {
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourcePortRange: "*",
        destinationPortRange: "53",
        description: "AllowDNS"
    },
    "ActiveDirectory-AllowKerberosAuthentication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourcePortRange: "*",
        destinationPortRange: "88",
        description: "AllowKerberosAuthentication"
    },
    "ActiveDirectory-AllowADReplicationTrust": {
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourcePortRange: "*",
        destinationPortRange: "445",
        description: "AllowADReplicationTrust"
    },
    "ActiveDirectory-AllowSMTPReplication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "25",
        description: "AllowSMTPReplication"
    },
    "ActiveDirectory-AllowRPCReplication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "135",
        description: "AllowRPCReplication"
    },
    "ActiveDirectory-AllowFileReplication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "5722",
        description: "AllowFileReplication"
    },
    "ActiveDirectory-AllowWindowsTime": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Udp",
        sourcePortRange: "*",
        destinationPortRange: "123",
        description: "AllowWindowsTime"
    },
    "ActiveDirectory-AllowPasswordChangeKerberes": {
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourcePortRange: "*",
        destinationPortRange: "464",
        description: "AllowPasswordChangeKerberes"
    },
    "ActiveDirectory-AllowDFSGroupPolicy": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Udp",
        sourcePortRange: "*",
        destinationPortRange: "138",
        description: "AllowDFSGroupPolicy"
    },
    "ActiveDirectory-AllowADDSWebServices": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "9389",
        description: "AllowADDSWebServices"
    },
    "ActiveDirectory-AllowNETBIOSAuthentication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Udp",
        sourcePortRange: "*",
        destinationPortRange: "137",
        description: "AllowNETBIOSAuthentication"
    },
    "ActiveDirectory-AllowNETBIOSReplication": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "139",
        description: "AllowNETBIOSReplication"
    },

    // Database rules
    "Cassandra": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "9042",
        description: "Cassandra"
    },
    "Cassandra-JMX": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "7199",
        description: "Cassandra-JMX"
    },
    "Cassandra-Thrift": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "9160",
        description: "Cassandra-Thrift"
    },
    "CouchDB": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "5984",
        description: "CouchDB"
    },
    "CouchDB-HTTPS": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "6984",
        description: "CouchDB-HTTPS"
    },
    "MongoDB": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "27017",
        description: "MongoDB"
    },
    "MySQL": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "3306",
        description: "MySQL"
    },
    "MSSQL": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "1433",
        description: "MSSQL"
    },
    "PostgreSQL": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "5432",
        description: "PostgreSQL"
    },
    "Redis": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "6379",
        description: "Redis"
    },

    // DNS rules
    "DNS-TCP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "53",
        description: "DNS-TCP"
    },
    "DNS-UDP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Udp",
        sourcePortRange: "*",
        destinationPortRange: "53",
        description: "DNS-UDP"
    },

    // Web rules
    "HTTP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "80",
        description: "HTTP"
    },
    "HTTPS": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "443",
        description: "HTTPS"
    },
    "DynamicPorts": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "49152-65535",
        description: "DynamicPorts"
    },

    // Cache and Search
    "ElasticSearch": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "9200-9300",
        description: "ElasticSearch"
    },
    "Memcached": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "11211",
        description: "Memcached"
    },

    // Email rules
    "IMAP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "143",
        description: "IMAP"
    },
    "IMAPS": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "993",
        description: "IMAPS"
    },
    "POP3": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "110",
        description: "POP3"
    },
    "POP3S": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "995",
        description: "POP3S"
    },
    "SMTP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "25",
        description: "SMTP"
    },
    "SMTPS": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "465",
        description: "SMTPS"
    },

    // File transfer
    "FTP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "21",
        description: "FTP"
    },

    // LDAP
    "LDAP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "389",
        description: "LDAP"
    },

    // Message Queue
    "RabbitMQ": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "5672",
        description: "RabbitMQ"
    },

    // Remote Access
    "RDP": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "3389",
        description: "RDP"
    },
    "SSH": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "22",
        description: "SSH"
    },
    "WinRM": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "5986",
        description: "WinRM"
    },

    // Other
    "Kestrel": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "22133",
        description: "Kestrel"
    },
    "Neo4J": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "7474",
        description: "Neo4J"
    },
    "Riak": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "8093",
        description: "Riak"
    },
    "Riak-JMX": {
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourcePortRange: "*",
        destinationPortRange: "8985",
        description: "Riak-JMX"
    }
};

// Add a validation function
function validatePriority(priority: number): void {
    if (priority < 100 || priority > 4096) {
        throw new Error(`Priority must be between 100 and 4096, got ${priority}`);
    }
}
