use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Compliance {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "RelatedRequirements")]
    related_requirements: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Malware {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "Type")]
    type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    #[serde(rename = "DestinationDomain")]
    destination_domain: String,
    #[serde(rename = "DestinationIpV4")]
    destination_ip_v4: String,
    #[serde(rename = "DestinationIpV6")]
    destination_ip_v6: String,
    #[serde(rename = "DestinationPort")]
    destination_port: i32,
    #[serde(rename = "Direction")]
    direction: String,
    #[serde(rename = "Protocol")]
    protocol: String,
    #[serde(rename = "SourceDomain")]
    source_domain: String,
    #[serde(rename = "SourceIpV4")]
    source_ip_v4: String,
    #[serde(rename = "SourceIpV6")]
    source_ip_v6: String,
    #[serde(rename = "SourceMac")]
    source_mac: String,
    #[serde(rename = "SourcePort")]
    source_port: i32,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    #[serde(rename = "Text")]
    text: String,
    #[serde(rename = "UpdatedAt")]
    updated_at: String,
    #[serde(rename = "UpdatedBy")]
    updated_by: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(rename = "LaunchedAt")]
    launched_at: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ParentPid")]
    parent_pid: i64,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Pid")]
    pid: i64,
    #[serde(rename = "TerminatedAt")]
    terminated_at: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductFields {
    //TODO: How do we represent this?
    //Type: Map of up to 50 key-value pairs
    string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedFinding {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "ProductArn")]
    product_arn: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Remediation {
    #[serde(rename = "Recommendation")]
    recommendation: Recommendation,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    #[serde(rename = "Text")]
    text: String,
    #[serde(rename = "Url")]
    url: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    #[serde(rename = "Details")]
    details: Details,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Partition")]
    partition: String,
    #[serde(rename = "Region")]
    region: String,
    #[serde(rename = "Tags")]
    tags: Tags,
    #[serde(rename = "Type")]
    type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Details {
    #[serde(rename = "AwsCloudFrontDistribution")]
    aws_cloud_front_distribution: AwsCloudFrontDistribution,
    #[serde(rename = "AwsCodeBuildProject")]
    aws_code_build_project: AwsCodeBuildProject,
    #[serde(rename = "AwsEc2Instance")]
    aws_ec2_instance: AwsEc2Instance,
    #[serde(rename = "AwsEc2NetworkInterface")]
    aws_ec2_network_interface: AwsEc2NetworkInterface,
    #[serde(rename = "AwsEc2SecurityGroup")]
    aws_ec2_security_group: AwsEc2SecurityGroup,
    #[serde(rename = "AwsElasticSearchDomain")]
    aws_elastic_search_domain: AwsElasticSearchDomain,
    #[serde(rename = "AwsElbv2LoadBalancer")]
    aws_elbv2_load_balancer: AwsElbv2LoadBalancer,
    #[serde(rename = "AwsIamAccessKey")]
    aws_iam_access_key: AwsIamAccessKey,
    #[serde(rename = "AwsIamRole")]
    aws_iam_role: AwsIamRole,
    #[serde(rename = "AwsKmsKey")]
    aws_kms_key: AwsKmsKey,
    #[serde(rename = "AwsLambdaFunction")]
    aws_lambda_function: AwsLambdaFunction,
    #[serde(rename = "AwsLambdaLayerVersion")]
    aws_lambda_layer_version: AwsLambdaLayerVersion,
    #[serde(rename = "AwsRdsDbInstance")]
    aws_rds_db_instance: AwsRdsDbInstance,
    #[serde(rename = "AwsS3Bucket")]
    aws_s3_bucket: AwsS3Bucket,
    #[serde(rename = "AwsS3Object")]
    aws_s3_object: AwsS3Object,
    #[serde(rename = "AwsSnsTopic")]
    aws_sns_topic: AwsSnsTopic,
    #[serde(rename = "AwsSqsQueue")]
    aws_sqs_queue: AwsSqsQueue,
    #[serde(rename = "AwsWafWebAcl")]
    aws_waf_web_acl: AwsWafWebAcl,
    #[serde(rename = "Container")]
    container: Container,
    #[serde(rename = "Other")]
    other: Other,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudFrontDistribution {
    #[serde(rename = "DomainName")]
    domain_name: String,
    #[serde(rename = "Etag")]
    etag: String,
    #[serde(rename = "LastModifiedTime")]
    last_modified_time: String,
    #[serde(rename = "Logging")]
    logging: Logging,
    #[serde(rename = "Origins")]
    origins: Origins,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "WebAclId")]
    web_acl_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Logging {
    #[serde(rename = "Bucket")]
    bucket: String,
    #[serde(rename = "Enabled")]
    enabled: bool,
    #[serde(rename = "IncludeCookies")]
    include_cookies: bool,
    #[serde(rename = "Prefix")]
    prefix: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Origins {
    #[serde(rename = "Items")]
    items: Items,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Items {
    #[serde(rename = "OriginPath")]
    origin_path: String,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "DomainName")]
    domain_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCodeBuildProject {
    #[serde(rename = "EncryptionKey")]
    encryption_key: String,
    #[serde(rename = "Environment")]
    environment: CodeBuildEnvironment,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ServiceRole")]
    service_role: String,
    #[serde(rename = "Source")]
    source: Source,
    #[serde(rename = "VpcConfig")]
    vpc_config: VpcConfig,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeBuildEnvironment {
    #[serde(rename = "Type")]
    type_field: String,
    #[serde(rename = "Certificate")]
    certificate: String,
    #[serde(rename = "ImagePullCredentialsType")]
    image_pull_credentials_type: String,
    #[serde(rename = "RegistryCredential")]
    registry_credential: RegistryCredential,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryCredential {
    #[serde(rename = "Credential")]
    credential: String,
    #[serde(rename = "CredentialProvider")]
    credential_provider: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    #[serde(rename = "Type")]
    type_field: String,
    #[serde(rename = "Location")]
    location: String,
    #[serde(rename = "GitCloneDepth")]
    git_clone_depth: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpcConfig {
    #[serde(rename = "VpcId")]
    vpc_id: String,
    #[serde(rename = "Subnets")]
    subnets: Vec<String>,
    #[serde(rename = "SecurityGroupIds")]
    security_group_ids: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEc2Instance {
    #[serde(rename = "IamInstanceProfileArn")]
    iam_instance_profile_arn: String,
    #[serde(rename = "ImageId")]
    image_id: String,
    #[serde(rename = "IpV4Addresses")]
    ip_v4_addresses: Vec<String>,
    #[serde(rename = "IpV6Addresses")]
    ip_v6_addresses: Vec<String>,
    #[serde(rename = "KeyName")]
    key_name: String,
    #[serde(rename = "LaunchedAt")]
    launched_at: String,
    #[serde(rename = "SubnetId")]
    subnet_id: String,
    #[serde(rename = "Type")]
    type_field: String,
    #[serde(rename = "VpcId")]
    vpc_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEc2NetworkInterface {
    #[serde(rename = "Attachment")]
    attachment: Attachment,
    #[serde(rename = "SecurityGroups")]
    security_groups: Vec<SecurityGroup>,
    #[serde(rename = "NetworkInterfaceId")]
    network_interface_id: String,
    #[serde(rename = "SourceDestCheck")]
    source_dest_check: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    #[serde(rename = "AttachmentId")]
    attachment_id: String,
    #[serde(rename = "AttachTime")]
    attach_time: String,
    #[serde(rename = "DeleteOnTermination")]
    delete_on_termination: bool,
    #[serde(rename = "DeviceIndex")]
    device_index: u16,
    #[serde(rename = "InstanceId")]
    instance_id: String,
    #[serde(rename = "InstanceOwnerId")]
    instance_owner_id: String,
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityGroup {
    #[serde(rename = "GroupId")]
    group_id: String,
    #[serde(rename = "GroupName")]
    group_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEc2SecurityGroup {
    #[serde(rename = "GroupId")]
    group_id: String,
    #[serde(rename = "GroupName")]
    group_name: String,
    #[serde(rename = "IpPermissions")]
    ip_permissions: Vec<IpPermission>,
    #[serde(rename = "IpPermissionsEgress")]
    ip_permissions_egress: Vec<IpPermission>,
    #[serde(rename = "OwnerId")]
    owner_id: String,
    #[serde(rename = "VpcId")]
    vpc_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPermission {
    #[serde(rename = "FromPort")]
    from_port: i32,
    #[serde(rename = "IpProtocol")]
    ip_protocol: String,
    #[serde(rename = "IpRanges")]
    ip_ranges: Vec<IpRange>,
    #[serde(rename = "PrefixListIds")]
    prefix_list_ids: Vec<PrefixListId>,
    #[serde(rename = "ToPort")]
    to_port: i32,
    #[serde(rename = "UserIdGroupPairs")]
    user_id_group_pairs: Vec<UserIdGroupPair>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpRange {
    #[serde(rename = "CidrIp")]
    cidr_ip: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixListId {
    #[serde(rename = "PrefixListId")]
    prefix_list_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdGroupPair {
    #[serde(rename = "UserId")]
    user_id: String,
    #[serde(rename = "GroupId")]
    group_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElasticSearchDomain {
    #[serde(rename = "AccessPolicies")]
    access_policies: String,
    #[serde(rename = "DomainStatus")]
    domain_status: DomainStatus,
    #[serde(rename = "DomainEndpointOptions")]
    domain_endpoint_options: DomainEndpointOptions,
    #[serde(rename = "ElasticsearchVersion")]
    elasticsearch_version: String,
    #[serde(rename = "EncryptionAtRestOptions")]
    encryption_at_rest_options: EncryptionAtRestOptions,
    #[serde(rename = "NodeToNodeEncryptionOptions")]
    node_to_node_encryption_options: NodeToNodeEncryptionOptions,
    #[serde(rename = "VPCOptions")]
    vpcoptions: Vpcoptions,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainStatus {
    #[serde(rename = "DomainId")]
    domain_id: String,
    #[serde(rename = "DomainName")]
    domain_name: String,
    #[serde(rename = "Endpoint")]
    endpoint: String,
    #[serde(rename = "Endpoints")]
    endpoints: Endpoints,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoints {
    string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEndpointOptions {
    #[serde(rename = "EnforceHTTPS")]
    enforce_https: bool,
    #[serde(rename = "TLSSecurityPolicy")]
    tlssecurity_policy: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionAtRestOptions {
    #[serde(rename = "Enabled")]
    enabled: bool,
    #[serde(rename = "KmsKeyId")]
    kms_key_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeToNodeEncryptionOptions {
    #[serde(rename = "Enabled")]
    enabled: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(rename = "VPCOptions")]
pub struct Vpcoptions {
    #[serde(rename = "AvailabilityZones")]
    availability_zones: Vec<String>,
    #[serde(rename = "SecurityGroupIds")]
    security_group_ids: Vec<String>,
    #[serde(rename = "SubnetIds")]
    subnet_ids: Vec<String>,
    #[serde(rename = "VPCId")]
    vpcid: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsElbv2LoadBalancer {
    #[serde(rename = "AvailabilityZones")]
    availability_zones: AvailabilityZones,
    #[serde(rename = "CanonicalHostedZoneId")]
    canonical_hosted_zone_id: String,
    #[serde(rename = "CreatedTime")]
    created_time: String,
    #[serde(rename = "DNSName")]
    dnsname: String,
    #[serde(rename = "IpAddressType")]
    ip_address_type: String,
    #[serde(rename = "Scheme")]
    scheme: String,
    #[serde(rename = "SecurityGroups")]
    security_groups: Vec<String>,
    #[serde(rename = "State")]
    state: State,
    #[serde(rename = "Type")]
    type_field: String,
    #[serde(rename = "VpcId")]
    vpc_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityZones {
    #[serde(rename = "SubnetId")]
    subnet_id: String,
    #[serde(rename = "ZoneName")]
    zone_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Reason")]
    reason: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIamAccessKey {
    #[serde(rename = "CreatedAt")]
    created_at: String,
    #[serde(rename = "PrincipalId")]
    principal_id: String,
    #[serde(rename = "PrincipalName")]
    principal_name: String,
    #[serde(rename = "PrincipalType")]
    principal_type: String,
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIamRole {
    #[serde(rename = "AssumeRolePolicyDocument")]
    assume_role_policy_document: String,
    #[serde(rename = "CreateDate")]
    create_date: String,
    #[serde(rename = "MaxSessionDuration")]
    max_session_duration: u32,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "RoleId")]
    role_id: String,
    #[serde(rename = "RoleName")]
    role_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKmsKey {
    #[serde(rename = "AWSAccountId")]
    awsaccount_id: String,
    #[serde(rename = "CreationDate")]
    creation_date: String,
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "KeyManager")]
    key_manager: String,
    #[serde(rename = "KeyState")]
    key_state: String,
    #[serde(rename = "Origin")]
    origin: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLambdaFunction {
    #[serde(rename = "Code")]
    code: Code,
    #[serde(rename = "CodeSha256")]
    code_sha256: String,
    #[serde(rename = "DeadLetterConfig")]
    dead_letter_config: DeadLetterConfig,
    #[serde(rename = "Environment")]
    environment: LambdaEnvironment,
    #[serde(rename = "FunctionName")]
    function_name: String,
    #[serde(rename = "Handler")]
    handler: String,
    #[serde(rename = "KmsKeyArn")]
    kms_key_arn: String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "Layers")]
    layers: Layers,
    #[serde(rename = "RevisionId")]
    revision_id: String,
    #[serde(rename = "Role")]
    role: String,
    #[serde(rename = "Runtime")]
    runtime: String,
    #[serde(rename = "Timeout")]
    timeout: String,
    #[serde(rename = "TracingConfig")]
    tracing_config: TracingConfig,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "VpcConfig")]
    vpc_config: VpcConfig2,
    #[serde(rename = "MasterArn")]
    master_arn: String,
    #[serde(rename = "MemorySize")]
    memory_size: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Code {
    #[serde(rename = "S3Bucket")]
    s3_bucket: String,
    #[serde(rename = "S3Key")]
    s3_key: String,
    #[serde(rename = "S3ObjectVersion")]
    s3_object_version: String,
    #[serde(rename = "ZipFile")]
    zip_file: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterConfig {
    #[serde(rename = "TargetArn")]
    target_arn: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LambdaEnvironment {
    #[serde(rename = "Variables")]
    variables: Variables,
    #[serde(rename = "Error")]
    error: Error,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variables {
    string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    #[serde(rename = "ErrorCode")]
    error_code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layers {
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "CodeSize")]
    code_size: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracingConfig {
    #[serde(rename = "TracingConfig.Mode")]
    tracing_config_mode: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpcConfig2 {
    #[serde(rename = "SecurityGroupIds")]
    security_group_ids: Vec<String>,
    #[serde(rename = "SubnetIds")]
    subnet_ids: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsLambdaLayerVersion {
    #[serde(rename = "CompatibleRuntimes")]
    compatible_runtimes: Vec<String>,
    #[serde(rename = "CreatedDate")]
    created_date: String,
    #[serde(rename = "Version")]
    version: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsDbInstance {
    #[serde(rename = "AssociatedRoles")]
    associated_roles: Vec<AssociatedRole>,
    #[serde(rename = "CACertificateIdentifier")]
    cacertificate_identifier: String,
    #[serde(rename = "DBClusterIdentifier")]
    dbcluster_identifier: String,
    #[serde(rename = "DBInstanceClass")]
    dbinstance_class: String,
    #[serde(rename = "DBInstanceIdentifier")]
    dbinstance_identifier: String,
    #[serde(rename = "DbInstancePort")]
    db_instance_port: i32,
    #[serde(rename = "DbiResourceId")]
    dbi_resource_id: String,
    #[serde(rename = "DBName")]
    dbname: String,
    #[serde(rename = "DeletionProtection")]
    deletion_protection: bool,
    #[serde(rename = "Endpoint")]
    endpoint: Endpoint,
    #[serde(rename = "Engine")]
    engine: String,
    #[serde(rename = "EngineVersion")]
    engine_version: String,
    #[serde(rename = "IAMDatabaseAuthenticationEnabled")]
    iamdatabase_authentication_enabled: bool,
    #[serde(rename = "InstanceCreateTime")]
    instance_create_time: String,
    #[serde(rename = "KmsKeyId")]
    kms_key_id: String,
    #[serde(rename = "liclyAccessible")]
    licly_accessible: bool,
    #[serde(rename = "TdeCredentialArn")]
    tde_credential_arn: String,
    #[serde(rename = "StorageEncrypted")]
    storage_encrypted: bool,
    #[serde(rename = "VpcSecurityGroups")]
    vpc_security_groups: Vec<VpcSecurityGroup>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociatedRole {
    #[serde(rename = "RoleArn")]
    role_arn: String,
    #[serde(rename = "FeatureName")]
    feature_name: String,
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "Port")]
    port: i32,
    #[serde(rename = "HostedZoneId")]
    hosted_zone_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpcSecurityGroup {
    #[serde(rename = "VpcSecurityGroupId")]
    vpc_security_group_id: String,
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3Bucket {
    #[serde(rename = "CreatedAt")]
    created_at: String,
    #[serde(rename = "OwnerId")]
    owner_id: String,
    #[serde(rename = "OwnerName")]
    owner_name: String,
    #[serde(rename = "ServerSideEncryptionConfiguration")]
    server_side_encryption_configuration: ServerSideEncryptionConfiguration,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSideEncryptionConfiguration {
    #[serde(rename = "Rules")]
    rules: Vec<SSERules>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSERules {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    apply_server_side_encryption_by_default: ApplyServerSideEncryptionByDefault,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyServerSideEncryptionByDefault {
    #[serde(rename = "KMSMasterKeyID")]
    kmsmaster_key_id: String,
    #[serde(rename = "SSEAlgorithm")]
    ssealgorithm: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3Object {
    #[serde(rename = "ContentType")]
    content_type: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ServerSideEncryption")]
    server_side_encryption: String,
    #[serde(rename = "SSEKMSKeyId")]
    ssekmskey_id: String,
    #[serde(rename = "VersionId")]
    version_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSnsTopic {
    #[serde(rename = "KmsMasterKeyId")]
    kms_master_key_id: String,
    #[serde(rename = "Owner")]
    owner: String,
    #[serde(rename = "Subscription")]
    subscription: Subscription,
    #[serde(rename = "TopicName")]
    topic_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    #[serde(rename = "Endpoint")]
    endpoint: String,
    #[serde(rename = "Protocol")]
    protocol: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSqsQueue {
    #[serde(rename = "DeadLetterTargetArn")]
    dead_letter_target_arn: String,
    #[serde(rename = "KmsDataKeyReusePeriodSeconds")]
    kms_data_key_reuse_period_seconds: u64,
    #[serde(rename = "KmsMasterKeyId")]
    kms_master_key_id: String,
    #[serde(rename = "QueueName")]
    queue_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsWafWebAcl {
    #[serde(rename = "DefaultAction")]
    default_action: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Rules")]
    rules: Vec<WafRules>,
    #[serde(rename = "WebAclId")]
    web_acl_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WafRules {
    #[serde(rename = "Action")]
    action: Action,
    #[serde(rename = "ExcludedRules")]
    excluded_rules: Vec<ExcludedRule>,
    #[serde(rename = "OverrideAction")]
    override_action: OverrideAction,
    #[serde(rename = "Priority")]
    priority: u32,
    #[serde(rename = "RuleId")]
    rule_id: String,
    #[serde(rename = "Type")]
    type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    #[serde(rename = "Type")]
    type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludedRule {
    #[serde(rename = "RuleId")]
    rule_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideAction {
    #[serde(rename = "Type")]
    type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    #[serde(rename = "ImageId")]
    image_id: String,
    #[serde(rename = "ImageName")]
    image_name: String,
    #[serde(rename = "LaunchedAt")]
    launched_at: String,
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Other {
    string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tags {
    string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Severity {
    #[serde(rename = "Label")]
    label: String,
    #[serde(rename = "Normalized")]
    normalized: u32,
    #[serde(rename = "Product")]
    pub(crate) product: u32,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatIntelIndicator {
    #[serde(rename = "Category")]
    category: String,
    #[serde(rename = "LastObservedAt")]
    last_observed_at: String,
    #[serde(rename = "Source")]
    source: String,
    #[serde(rename = "SourceUrl")]
    source_url: String,
    #[serde(rename = "Type")]
    type_field: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDefinedFields {
    string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workflow {
    #[serde(rename = "Status")]
    status: String,
}
