use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Findings {
    #[serde(rename = "Findings")]
    pub findings: Vec<Finding>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(rename = "AwsAccountId")]
    pub aws_account_id: String,
    #[serde(rename = "Compliance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub compliance: Option<Compliance>,
    #[serde(rename = "Confidence")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub confidence: Option<i64>,
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "Criticality")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub criticality: Option<i64>,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "FirstObservedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub first_observed_at: Option<String>,
    #[serde(rename = "GeneratorId")]
    pub generator_id: String,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "LastObservedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub last_observed_at: Option<String>,
    #[serde(rename = "Malware")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub malware: Option<Vec<Malware>>,
    #[serde(rename = "Network")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub network: Option<Network>,
    #[serde(rename = "Note")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub note: Option<Note>,
    #[serde(rename = "Process")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub process: Option<Process>,
    #[serde(rename = "ProductArn")]
    pub product_arn: String,
    #[serde(rename = "ProductFields")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub product_fields: Option<ProductFields>,
    #[serde(rename = "RecordState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub record_state: Option<String>,
    #[serde(rename = "RelatedFindings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub related_findings: Option<Vec<RelatedFinding>>,
    #[serde(rename = "Remediation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub remediation: Option<Remediation>,
    #[serde(rename = "Resources")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub resources: Option<Vec<Resource>>,
    #[serde(rename = "SchemaVersion")]
    pub schema_version: String,
    #[serde(rename = "Severity")]
    pub severity: Severity,
    #[serde(rename = "SourceUrl")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(rename = "ThreatIntelIndicators")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub threat_intel_indicators: Option<Vec<ThreatIntelIndicator>>,
    #[serde(rename = "Title")]
    pub title: String,
    //TODO: This should be an enum of allowed types
    #[serde(rename = "Types")]
    pub types: Vec<String>,
    #[serde(rename = "UpdatedAt")]
    pub updated_at: String,
    #[serde(rename = "UserDefinedFields")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub user_defined_fields: Option<UserDefinedFields>,
    #[serde(rename = "VerificationState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub verification_state: Option<String>,
    #[serde(rename = "Workflow")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub workflow: Option<Workflow>,
    #[serde(rename = "WorkflowState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub workflow_state: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Compliance {
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "RelatedRequirements")]
    pub related_requirements: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Malware {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    #[serde(rename = "DestinationDomain")]
    pub destination_domain: String,
    #[serde(rename = "DestinationIpV4")]
    pub destination_ip_v4: String,
    #[serde(rename = "DestinationIpV6")]
    pub destination_ip_v6: String,
    #[serde(rename = "DestinationPort")]
    pub destination_port: i64,
    #[serde(rename = "Direction")]
    pub direction: String,
    #[serde(rename = "Protocol")]
    pub protocol: String,
    #[serde(rename = "SourceDomain")]
    pub source_domain: String,
    #[serde(rename = "SourceIpV4")]
    pub source_ip_v4: String,
    #[serde(rename = "SourceIpV6")]
    pub source_ip_v6: String,
    #[serde(rename = "SourceMac")]
    pub source_mac: String,
    #[serde(rename = "SourcePort")]
    pub source_port: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    #[serde(rename = "Text")]
    pub text: String,
    #[serde(rename = "UpdatedAt")]
    pub updated_at: String,
    #[serde(rename = "UpdatedBy")]
    pub updated_by: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(rename = "LaunchedAt")]
    pub launched_at: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ParentPid")]
    pub parent_pid: i64,
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "Pid")]
    pub pid: i64,
    #[serde(rename = "TerminatedAt")]
    pub terminated_at: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductFields {
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedFinding {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "ProductArn")]
    pub product_arn: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Remediation {
    #[serde(rename = "Recommendation")]
    pub recommendation: Recommendation,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    #[serde(rename = "Text")]
    pub text: String,
    #[serde(rename = "Url")]
    pub url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    #[serde(rename = "Details")]
    pub details: Details,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Partition")]
    pub partition: String,
    #[serde(rename = "Region")]
    pub region: String,
    #[serde(rename = "Tags")]
    pub tags: Tags,
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Details {
    #[serde(rename = "AwsCloudFrontDistribution")]
    pub aws_cloud_front_distribution: AwsCloudFrontDistribution,
    #[serde(rename = "AwsCodeBuildProject")]
    pub aws_code_build_project: AwsCodeBuildProject,
    #[serde(rename = "AwsEc2Instance")]
    pub aws_ec2_instance: AwsEc2Instance,
    #[serde(rename = "AwsEc2NetworkInterface")]
    pub aws_ec2_network_interface: AwsEc2NetworkInterface,
    #[serde(rename = "AwsEc2SecurityGroup")]
    pub aws_ec2_security_group: AwsEc2SecurityGroup,
    #[serde(rename = "AwsElasticSearchDomain")]
    pub aws_elastic_search_domain: AwsElasticSearchDomain,
    #[serde(rename = "AwsElbv2LoadBalancer")]
    pub aws_elbv2_load_balancer: AwsElbv2LoadBalancer,
    #[serde(rename = "AwsIamAccessKey")]
    pub aws_iam_access_key: AwsIamAccessKey,
    #[serde(rename = "AwsIamRole")]
    pub aws_iam_role: AwsIamRole,
    #[serde(rename = "AwsKmsKey")]
    pub aws_kms_key: AwsKmsKey,
    #[serde(rename = "AwsLambdaFunction")]
    pub aws_lambda_function: AwsLambdaFunction,
    #[serde(rename = "AwsLambdaLayerVersion")]
    pub aws_lambda_layer_version: AwsLambdaLayerVersion,
    #[serde(rename = "AwsRdsDbInstance")]
    pub aws_rds_db_instance: AwsRdsDbInstance,
    #[serde(rename = "AwsS3Bucket")]
    pub aws_s3_bucket: AwsS3Bucket,
    #[serde(rename = "AwsS3Object")]
    pub aws_s3_object: AwsS3Object,
    #[serde(rename = "AwsSnsTopic")]
    pub aws_sns_topic: AwsSnsTopic,
    #[serde(rename = "AwsSqsQueue")]
    pub aws_sqs_queue: AwsSqsQueue,
    #[serde(rename = "AwsWafWebAcl")]
    pub aws_waf_web_acl: AwsWafWebAcl,
    #[serde(rename = "Container")]
    pub container: Container,
    #[serde(rename = "Other")]
    pub other: Other,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudFrontDistribution {
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "Etag")]
    pub etag: String,
    #[serde(rename = "LastModifiedTime")]
    pub last_modified_time: String,
    #[serde(rename = "Logging")]
    pub logging: Logging,
    #[serde(rename = "Origins")]
    pub origins: Origins,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "WebAclId")]
    pub web_acl_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Logging {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "IncludeCookies")]
    pub include_cookies: bool,
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Origins {
    #[serde(rename = "Items")]
    pub items: Items,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Items {
    #[serde(rename = "OriginPath")]
    pub origin_path: String,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "DomainName")]
    pub domain_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodeBuildProject {
    #[serde(rename = "EncryptionKey")]
    pub encryption_key: String,
    #[serde(rename = "Environment")]
    pub environment: Environment,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ServiceRole")]
    pub service_role: String,
    #[serde(rename = "Source")]
    pub source: Source,
    #[serde(rename = "VpcConfig")]
    pub vpc_config: VpcConfig,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    #[serde(rename = "Type")]
    pub type_field: String,
    #[serde(rename = "Certificate")]
    pub certificate: String,
    #[serde(rename = "ImagePullCredentialsType")]
    pub image_pull_credentials_type: String,
    #[serde(rename = "RegistryCredential")]
    pub registry_credential: RegistryCredential,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryCredential {
    #[serde(rename = "Credential")]
    pub credential: String,
    #[serde(rename = "CredentialProvider")]
    pub credential_provider: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    #[serde(rename = "Type")]
    pub type_field: String,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "GitCloneDepth")]
    pub git_clone_depth: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpcConfig {
    #[serde(rename = "VpcId")]
    pub vpc_id: String,
    #[serde(rename = "Subnets")]
    pub subnets: Vec<String>,
    #[serde(rename = "SecurityGroupIds")]
    pub security_group_ids: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEc2Instance {
    #[serde(rename = "IamInstanceProfileArn")]
    pub iam_instance_profile_arn: String,
    #[serde(rename = "ImageId")]
    pub image_id: String,
    #[serde(rename = "IpV4Addresses")]
    pub ip_v4_addresses: Vec<String>,
    #[serde(rename = "IpV6Addresses")]
    pub ip_v6_addresses: Vec<String>,
    #[serde(rename = "KeyName")]
    pub key_name: String,
    #[serde(rename = "LaunchedAt")]
    pub launched_at: String,
    #[serde(rename = "SubnetId")]
    pub subnet_id: String,
    #[serde(rename = "Type")]
    pub type_field: String,
    #[serde(rename = "VpcId")]
    pub vpc_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEc2NetworkInterface {
    #[serde(rename = "Attachment")]
    pub attachment: Attachment,
    #[serde(rename = "SecurityGroups")]
    pub security_groups: Vec<SecurityGroup>,
    #[serde(rename = "NetworkInterfaceId")]
    pub network_interface_id: String,
    #[serde(rename = "SourceDestCheck")]
    pub source_dest_check: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    #[serde(rename = "AttachmentId")]
    pub attachment_id: String,
    #[serde(rename = "AttachTime")]
    pub attach_time: String,
    #[serde(rename = "DeleteOnTermination")]
    pub delete_on_termination: bool,
    #[serde(rename = "DeviceIndex")]
    pub device_index: i64,
    #[serde(rename = "InstanceId")]
    pub instance_id: String,
    #[serde(rename = "InstanceOwnerId")]
    pub instance_owner_id: String,
    #[serde(rename = "Status")]
    pub status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityGroup {
    #[serde(rename = "GroupId")]
    pub group_id: String,
    #[serde(rename = "GroupName")]
    pub group_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEc2SecurityGroup {
    #[serde(rename = "GroupId")]
    pub group_id: String,
    #[serde(rename = "GroupName")]
    pub group_name: String,
    #[serde(rename = "IpPermissions")]
    pub ip_permissions: Vec<IpPermission>,
    #[serde(rename = "IpPermissionsEgress")]
    pub ip_permissions_egress: Vec<IpPermissionsEgress>,
    #[serde(rename = "OwnerId")]
    pub owner_id: String,
    #[serde(rename = "VpcId")]
    pub vpc_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPermission {
    #[serde(rename = "FromPort")]
    pub from_port: i64,
    #[serde(rename = "IpProtocol")]
    pub ip_protocol: String,
    #[serde(rename = "IpRanges")]
    pub ip_ranges: Vec<IpRange>,
    #[serde(rename = "PrefixListIds")]
    pub prefix_list_ids: Vec<PrefixListId>,
    #[serde(rename = "ToPort")]
    pub to_port: i64,
    #[serde(rename = "UserIdGroupPairs")]
    pub user_id_group_pairs: Vec<UserIdGroupPair>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpRange {
    #[serde(rename = "CidrIp")]
    pub cidr_ip: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListId {
    #[serde(rename = "PrefixListId")]
    pub prefix_list_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdGroupPair {
    #[serde(rename = "UserId")]
    pub user_id: String,
    #[serde(rename = "GroupId")]
    pub group_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPermissionsEgress {
    #[serde(rename = "FromPort")]
    pub from_port: i64,
    #[serde(rename = "IpProtocol")]
    pub ip_protocol: String,
    #[serde(rename = "IpRanges")]
    pub ip_ranges: Vec<IpRange2>,
    #[serde(rename = "PrefixListIds")]
    pub prefix_list_ids: Vec<PrefixListId2>,
    #[serde(rename = "ToPort")]
    pub to_port: i64,
    #[serde(rename = "UserIdGroupPairs")]
    pub user_id_group_pairs: Vec<UserIdGroupPair2>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpRange2 {
    #[serde(rename = "CidrIp")]
    pub cidr_ip: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListId2 {
    #[serde(rename = "PrefixListId")]
    pub prefix_list_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdGroupPair2 {
    #[serde(rename = "UserId")]
    pub user_id: String,
    #[serde(rename = "GroupId")]
    pub group_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElasticSearchDomain {
    #[serde(rename = "AccessPolicies")]
    pub access_policies: String,
    #[serde(rename = "DomainStatus")]
    pub domain_status: DomainStatus,
    #[serde(rename = "DomainEndpointOptions")]
    pub domain_endpoint_options: DomainEndpointOptions,
    #[serde(rename = "ElasticsearchVersion")]
    pub elasticsearch_version: String,
    #[serde(rename = "EncryptionAtRestOptions")]
    pub encryption_at_rest_options: EncryptionAtRestOptions,
    #[serde(rename = "NodeToNodeEncryptionOptions")]
    pub node_to_node_encryption_options: NodeToNodeEncryptionOptions,
    #[serde(rename = "VPCOptions")]
    pub vpcoptions: Vpcoptions,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainStatus {
    #[serde(rename = "DomainId")]
    pub domain_id: String,
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
    #[serde(rename = "Endpoints")]
    pub endpoints: Endpoints,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoints {
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEndpointOptions {
    #[serde(rename = "EnforceHTTPS")]
    pub enforce_https: bool,
    #[serde(rename = "TLSSecurityPolicy")]
    pub tlssecurity_policy: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionAtRestOptions {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "KmsKeyId")]
    pub kms_key_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeToNodeEncryptionOptions {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vpcoptions {
    #[serde(rename = "AvailabilityZones")]
    pub availability_zones: Vec<String>,
    #[serde(rename = "SecurityGroupIds")]
    pub security_group_ids: Vec<String>,
    #[serde(rename = "SubnetIds")]
    pub subnet_ids: Vec<String>,
    #[serde(rename = "VPCId")]
    pub vpcid: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbv2LoadBalancer {
    #[serde(rename = "AvailabilityZones")]
    pub availability_zones: AvailabilityZones,
    #[serde(rename = "CanonicalHostedZoneId")]
    pub canonical_hosted_zone_id: String,
    #[serde(rename = "CreatedTime")]
    pub created_time: String,
    #[serde(rename = "DNSName")]
    pub dnsname: String,
    #[serde(rename = "IpAddressType")]
    pub ip_address_type: String,
    #[serde(rename = "Scheme")]
    pub scheme: String,
    #[serde(rename = "SecurityGroups")]
    pub security_groups: Vec<String>,
    #[serde(rename = "State")]
    pub state: State,
    #[serde(rename = "Type")]
    pub type_field: String,
    #[serde(rename = "VpcId")]
    pub vpc_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityZones {
    #[serde(rename = "SubnetId")]
    pub subnet_id: String,
    #[serde(rename = "ZoneName")]
    pub zone_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Reason")]
    pub reason: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIamAccessKey {
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "PrincipalId")]
    pub principal_id: String,
    #[serde(rename = "PrincipalName")]
    pub principal_name: String,
    #[serde(rename = "PrincipalType")]
    pub principal_type: String,
    #[serde(rename = "Status")]
    pub status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIamRole {
    #[serde(rename = "AssumeRolePolicyDocument")]
    pub assume_role_policy_document: String,
    #[serde(rename = "CreateDate")]
    pub create_date: String,
    #[serde(rename = "MaxSessionDuration")]
    pub max_session_duration: i64,
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "RoleId")]
    pub role_id: String,
    #[serde(rename = "RoleName")]
    pub role_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsKey {
    #[serde(rename = "AWSAccountId")]
    pub awsaccount_id: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
    #[serde(rename = "KeyId")]
    pub key_id: String,
    #[serde(rename = "KeyManager")]
    pub key_manager: String,
    #[serde(rename = "KeyState")]
    pub key_state: String,
    #[serde(rename = "Origin")]
    pub origin: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLambdaFunction {
    #[serde(rename = "Code")]
    pub code: Code,
    #[serde(rename = "CodeSha256")]
    pub code_sha256: String,
    #[serde(rename = "DeadLetterConfig")]
    pub dead_letter_config: DeadLetterConfig,
    #[serde(rename = "Environment")]
    pub environment: Environment2,
    #[serde(rename = "FunctionName")]
    pub function_name: String,
    #[serde(rename = "Handler")]
    pub handler: String,
    #[serde(rename = "KmsKeyArn")]
    pub kms_key_arn: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "Layers")]
    pub layers: Layers,
    #[serde(rename = "RevisionId")]
    pub revision_id: String,
    #[serde(rename = "Role")]
    pub role: String,
    #[serde(rename = "Runtime")]
    pub runtime: String,
    #[serde(rename = "Timeout")]
    pub timeout: String,
    #[serde(rename = "TracingConfig")]
    pub tracing_config: TracingConfig,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "VpcConfig")]
    pub vpc_config: VpcConfig2,
    #[serde(rename = "MasterArn")]
    pub master_arn: String,
    #[serde(rename = "MemorySize")]
    pub memory_size: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Code {
    #[serde(rename = "S3Bucket")]
    pub s3_bucket: String,
    #[serde(rename = "S3Key")]
    pub s3_key: String,
    #[serde(rename = "S3ObjectVersion")]
    pub s3_object_version: String,
    #[serde(rename = "ZipFile")]
    pub zip_file: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterConfig {
    #[serde(rename = "TargetArn")]
    pub target_arn: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Environment2 {
    #[serde(rename = "Variables")]
    pub variables: Variables,
    #[serde(rename = "Error")]
    pub error: Error,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variables {
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    #[serde(rename = "ErrorCode")]
    pub error_code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layers {
    #[serde(rename = "Arn")]
    pub arn: String,
    #[serde(rename = "CodeSize")]
    pub code_size: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracingConfig {
    #[serde(rename = "TracingConfig.Mode")]
    pub tracing_config_mode: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpcConfig2 {
    #[serde(rename = "SecurityGroupIds")]
    pub security_group_ids: Vec<String>,
    #[serde(rename = "SubnetIds")]
    pub subnet_ids: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLambdaLayerVersion {
    #[serde(rename = "CompatibleRuntimes")]
    pub compatible_runtimes: Vec<String>,
    #[serde(rename = "CreatedDate")]
    pub created_date: String,
    #[serde(rename = "Version")]
    pub version: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsDbInstance {
    #[serde(rename = "AssociatedRoles")]
    pub associated_roles: Vec<AssociatedRole>,
    #[serde(rename = "CACertificateIdentifier")]
    pub cacertificate_identifier: String,
    #[serde(rename = "DBClusterIdentifier")]
    pub dbcluster_identifier: String,
    #[serde(rename = "DBInstanceClass")]
    pub dbinstance_class: String,
    #[serde(rename = "DBInstanceIdentifier")]
    pub dbinstance_identifier: String,
    #[serde(rename = "DbInstancePort")]
    pub db_instance_port: i64,
    #[serde(rename = "DbiResourceId")]
    pub dbi_resource_id: String,
    #[serde(rename = "DBName")]
    pub dbname: String,
    #[serde(rename = "DeletionProtection")]
    pub deletion_protection: bool,
    #[serde(rename = "Endpoint")]
    pub endpoint: Endpoint,
    #[serde(rename = "Engine")]
    pub engine: String,
    #[serde(rename = "EngineVersion")]
    pub engine_version: String,
    #[serde(rename = "IAMDatabaseAuthenticationEnabled")]
    pub iamdatabase_authentication_enabled: bool,
    #[serde(rename = "InstanceCreateTime")]
    pub instance_create_time: String,
    #[serde(rename = "KmsKeyId")]
    pub kms_key_id: String,
    #[serde(rename = "PubliclyAccessible")]
    pub publicly_accessible: bool,
    #[serde(rename = "TdeCredentialArn")]
    pub tde_credential_arn: String,
    #[serde(rename = "StorageEncrypted")]
    pub storage_encrypted: bool,
    #[serde(rename = "VpcSecurityGroups")]
    pub vpc_security_groups: Vec<VpcSecurityGroup>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociatedRole {
    #[serde(rename = "RoleArn")]
    pub role_arn: String,
    #[serde(rename = "FeatureName")]
    pub feature_name: String,
    #[serde(rename = "Status")]
    pub status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Port")]
    pub port: i64,
    #[serde(rename = "HostedZoneId")]
    pub hosted_zone_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpcSecurityGroup {
    #[serde(rename = "VpcSecurityGroupId")]
    pub vpc_security_group_id: String,
    #[serde(rename = "Status")]
    pub status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3Bucket {
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "OwnerId")]
    pub owner_id: String,
    #[serde(rename = "OwnerName")]
    pub owner_name: String,
    #[serde(rename = "ServerSideEncryptionConfiguration")]
    pub server_side_encryption_configuration: ServerSideEncryptionConfiguration,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSideEncryptionConfiguration {
    #[serde(rename = "Rules")]
    pub rules: Vec<Rule>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    pub apply_server_side_encryption_by_default: ApplyServerSideEncryptionByDefault,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyServerSideEncryptionByDefault {
    #[serde(rename = "KMSMasterKeyID")]
    pub kmsmaster_key_id: String,
    #[serde(rename = "SSEAlgorithm")]
    pub ssealgorithm: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3Object {
    #[serde(rename = "ContentType")]
    pub content_type: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ServerSideEncryption")]
    pub server_side_encryption: String,
    #[serde(rename = "SSEKMSKeyId")]
    pub ssekmskey_id: String,
    #[serde(rename = "VersionId")]
    pub version_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSnsTopic {
    #[serde(rename = "KmsMasterKeyId")]
    pub kms_master_key_id: String,
    #[serde(rename = "Owner")]
    pub owner: String,
    #[serde(rename = "Subscription")]
    pub subscription: Subscription,
    #[serde(rename = "TopicName")]
    pub topic_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    #[serde(rename = "Endpoint")]
    pub endpoint: String,
    #[serde(rename = "Protocol")]
    pub protocol: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSqsQueue {
    #[serde(rename = "DeadLetterTargetArn")]
    pub dead_letter_target_arn: String,
    #[serde(rename = "KmsDataKeyReusePeriodSeconds")]
    pub kms_data_key_reuse_period_seconds: i64,
    #[serde(rename = "KmsMasterKeyId")]
    pub kms_master_key_id: String,
    #[serde(rename = "QueueName")]
    pub queue_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafWebAcl {
    #[serde(rename = "DefaultAction")]
    pub default_action: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Rules")]
    pub rules: Vec<Rule2>,
    #[serde(rename = "WebAclId")]
    pub web_acl_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule2 {
    #[serde(rename = "Action")]
    pub action: Action,
    #[serde(rename = "ExcludedRules")]
    pub excluded_rules: Vec<ExcludedRule>,
    #[serde(rename = "OverrideAction")]
    pub override_action: OverrideAction,
    #[serde(rename = "Priority")]
    pub priority: i64,
    #[serde(rename = "RuleId")]
    pub rule_id: String,
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludedRule {
    #[serde(rename = "RuleId")]
    pub rule_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideAction {
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    #[serde(rename = "ImageId")]
    pub image_id: String,
    #[serde(rename = "ImageName")]
    pub image_name: String,
    #[serde(rename = "LaunchedAt")]
    pub launched_at: String,
    #[serde(rename = "Name")]
    pub name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Other {
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tags {
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Severity {
    #[serde(rename = "Label")]
    pub label: String,
    #[serde(rename = "Normalized")]
    pub normalized: i64,
    #[serde(rename = "Product")]
    pub product: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatIntelIndicator {
    #[serde(rename = "Category")]
    pub category: String,
    #[serde(rename = "LastObservedAt")]
    pub last_observed_at: String,
    #[serde(rename = "Source")]
    pub source: String,
    #[serde(rename = "SourceUrl")]
    pub source_url: String,
    #[serde(rename = "Type")]
    pub type_field: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDefinedFields {
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workflow {
    #[serde(rename = "Status")]
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let f = Finding {
            aws_account_id: "123".to_owned(),
            schema_version: "garbage".to_owned(),
            id: "garbage".to_owned(),
            product_arn: "garbage".to_owned(),
            generator_id: "foobar".to_owned(),
            types: vec!["foobar".to_owned()],
            // severity: Severity{
            //         label: "Product".to_owned(),
            //         product: 1,
            //         normalized: 1,
            //     }
            ..Default::default()
        };
        let j = serde_json::to_string(&f);
        println!("{}", j.unwrap());
    }
}
