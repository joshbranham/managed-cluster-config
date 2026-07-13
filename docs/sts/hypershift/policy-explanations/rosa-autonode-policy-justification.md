# ROSA Karpenter Controller Managed Policy Justification

## Overview

This document provides detailed justification for each permission in the ROSA Karpenter Controller managed policy. ROSA Karpenter Controller is an automatic node provisioning and scaling feature for Red Hat OpenShift Service on AWS (ROSA) clusters, similar to Karpenter functionality but integrated with ROSA's security model and operational patterns.

## Security Model

The ROSA Karpenter Controller policy follows the established ROSA security patterns:

- **Primary boundary**: Service-specific tagging using `red-hat-managed: "true"`
- **Resource creation**: Requires appropriate request tags for new resources
- **Resource modification**: Requires existing resource tags for managed resources
- **Combined operations**: Uses both request and resource tag conditions where appropriate

**Note (request tags on IAM create)**: `aws:RequestTag/red-hat-managed` is evaluated only when the **IAM API request** includes that tag (it is not the same as resource tags already stored on an object). For managed ROSA/HyperShift clusters, tags from `HostedControlPlane.spec.platform.aws` (including `red-hat-managed`) are merged into the guest `EC2NodeClass` and are intended to be passed when the upstream Karpenter AWS provider creates or tags instance profiles. This matches `sts_hcp_installer_permission_policy.json` for `CreateInstanceProfile` / `TagInstanceProfile`. **Validation**: confirm via CloudTrail (`CreateInstanceProfile` / `TagInstanceProfile` `requestParameters`) that tags are present on the request where this condition applies.

## Permission Groups and Justifications

### ReadPermissions

**Actions**: `ec2:Describe*`
**Resource**: `*`
**Justification**: Karpenter Controller requires comprehensive read access to understand the AWS environment for node placement decisions. These read-only operations are essential for:
- Discovering available instance types and pricing
- Understanding network topology (VPCs, subnets, security groups)
- Making informed scaling decisions based on resource availability

**Security**: Read operations pose minimal security risk and do not modify infrastructure.

### PricingReadActions

**Actions**: `pricing:GetProducts`
**Resource**: `*`
**Justification**: Enables cost-aware node provisioning by accessing AWS pricing information. Karpenter Controller can make optimal instance selection decisions based on cost considerations and spot instance pricing.

**Security**: Pricing service is global and read-only, posing no security risk.

### DescribeKMSKeysForEBSVolumeEncryption

**Actions**: `kms:DescribeKey`
**Resource**: `arn:aws:kms:*:*:key/*`
**Condition**: `StringEquals` / `aws:ResourceTag/red-hat`: `"true"`; `StringLike` / `kms:ViaService`: `ec2.*.amazonaws.com`
**Justification**: Required for Karpenter Controller to inspect customer-managed KMS key metadata (key state, key spec, usage) before launching instances with encrypted EBS volumes. Split into its own statement because `kms:DescribeKey` must not be scoped by encryption-context conditions — the API call carries no encryption context, so adding `kms:EncryptionContextKeys` would deny every `DescribeKey` request.

**Security**: Read-only metadata operation. Limited to KMS keys tagged `red-hat: true` and called via the EC2 service. No cryptographic or administrative capability.

### CryptoOpsForEBSVolumeEncryption

**Actions**: `kms:Decrypt`, `kms:ReEncryptFrom`, `kms:ReEncryptTo`, `kms:GenerateDataKeyWithoutPlaintext`
**Resource**: `arn:aws:kms:*:*:key/*`
**Condition**: `StringEquals` / `aws:ResourceTag/red-hat`: `"true"`; `StringLike` / `kms:ViaService`: `ec2.*.amazonaws.com`; `ForAllValues:StringEquals` / `kms:EncryptionContextKeys`: `["aws:ebs:id"]`
**Justification**: Required for EBS volume encryption when customers specify customer-managed KMS keys for node storage encryption. Karpenter Controller needs to generate data keys and decrypt/re-encrypt during instance creation and volume attach operations.

**Security**: Limited to KMS keys tagged `red-hat: true`, called via the EC2 service, and scoped to EBS volume operations via the `kms:EncryptionContextKeys` condition (`aws:ebs:id` is the standard EBS encryption-context key whose value is the volume ID). No administrative permissions.

### CreateGrantForEBSVolumeEncryption

**Actions**: `kms:CreateGrant`
**Resource**: `arn:aws:kms:*:*:key/*`
**Condition**: `Bool` / `kms:GrantIsForAWSResource`: `true`; `StringLike` / `kms:ViaService`: `ec2.*.amazonaws.com`; `StringEquals` / `kms:GrantConstraintType`: `"EncryptionContextSubset"`; `ForAllValues:StringEquals` / `kms:GrantOperations`: `["Decrypt", "GenerateDataKeyWithoutPlaintext", "ReEncryptFrom", "ReEncryptTo"]`; `ForAllValues:StringEquals` / `kms:EncryptionContextKeys`: `["aws:ebs:id"]`
**Justification**: Enables Karpenter Controller to create KMS grants so that EC2 can perform cryptographic operations on customer-managed keys for EBS volume encryption. The grant constraint type `EncryptionContextSubset` ensures the grant only applies when the EBS encryption context is present, while allowing EC2 to include additional context keys. `kms:GrantOperations` restricts the grant to the operations EC2 needs for EBS volume lifecycle: data key generation, decryption, and re-encryption.

**Security**: Grants restricted to AWS resources (`GrantIsForAWSResource`), EC2 service (`ViaService`), EBS operations (`EncryptionContextKeys`), and a fixed set of crypto operations (`GrantOperations`). The `EncryptionContextSubset` constraint type prevents the grant from being used outside EBS volume operations.

### CreateEC2Resources

**Actions**: `ec2:RunInstances`, `ec2:CreateFleet`
**Resources**: Security groups, subnets, capacity reservations
**Justification**: Core functionality for launching EC2 instances and creating fleets for automated node provisioning. These resources are prerequisite dependencies for instance creation.

**Security**: Limited to specific resource types needed for instance creation. No conditions required as these are prerequisite resources.

### CreateEC2ResourcesWithApprovedAMIs

**Actions**: `ec2:RunInstances`, `ec2:CreateFleet`
**Resource**: `arn:aws:ec2:*::image/*`
**Condition**: `ec2:Owner`: `"531415883065"`, `"251351625822"`, `"210686502322"`
**Justification**: Allows Karpenter Controller to launch instances using only approved ROSA AMIs from trusted publisher accounts. These owner accounts represent Red Hat and AWS official AMI publishers for ROSA-compatible images.

**Security**: Strict AMI access control prevents use of unauthorized or potentially compromised images. Only Red Hat and AWS-approved AMIs can be used for node provisioning, maintaining ROSA security standards.

### CreateEC2ResourcesWithTags

**Actions**: `ec2:RunInstances`, `ec2:CreateFleet`, `ec2:CreateLaunchTemplate`
**Resources**: Fleets, instances, volumes, network interfaces, launch templates, spot requests
**Condition**: `aws:RequestTag/red-hat-managed: "true"`
**Justification**: Primary Karpenter Controller operations for creating managed infrastructure. The ROSA service boundary is enforced through required tagging.

**Security**: Service boundary enforced through mandatory `red-hat-managed: "true"` request tag. Only resources with proper tagging can be created.

### CreateEC2ResourcesLaunchTemplate

**Actions**: `ec2:RunInstances`, `ec2:CreateFleet`
**Resource**: `arn:aws:ec2:*:*:launch-template/*`
**Condition**: `aws:ResourceTag/red-hat-managed: "true"`
**Justification**: Allows Karpenter Controller to use existing ROSA-managed launch templates for consistent node provisioning. Launch templates ensure standardized configuration across all managed nodes.

**Security**: Scoped to ROSA-managed launch templates only through resource tag condition.

### CreateTagsOnResources

**Actions**: `ec2:CreateTags`
**Resources**: Fleets, instances, volumes, network interfaces, launch templates, spot requests
**Conditions**: 
- `ec2:CreateAction`: Limited to creation actions
- `aws:RequestTag/red-hat-managed: "true"`
**Justification**: Essential for maintaining service boundaries and resource ownership. Tags enable proper resource lifecycle management and cost allocation.

**Security**: Tagging restricted to resource creation time and requires ROSA management tag.

### ManageTagsOnManagedResources

**Actions**: `ec2:CreateTags`
**Resource**: `arn:aws:ec2:*:*:instance/*`
**Condition**: `aws:ResourceTag/red-hat-managed: "true"`
**Justification**: Allows updating tags on existing managed instances for cluster integration, lifecycle management, and operational metadata. This enables Karpenter Controller to add labels, annotations, and other operational tags as needed for cluster functionality.

**Security**: Restricted to ROSA-managed instances only through resource tag condition. Tag key restrictions have been relaxed to allow operational flexibility while maintaining service boundary through the red-hat-managed tag requirement.

### TerminateManagedResources

**Actions**: `ec2:TerminateInstances`, `ec2:DeleteLaunchTemplate`
**Resources**: Instances, launch templates
**Condition**: `aws:ResourceTag/red-hat-managed: "true"`
**Justification**: Required for scaling down operations and resource cleanup when demand decreases or nodes become unhealthy.

**Security**: Service boundary enforced through resource tag condition. Only ROSA-managed resources can be terminated.

### PassInstanceRole

**Actions**: `iam:PassRole`
**Resource**: `arn:aws:iam::*:role/*`
**Condition**: `iam:PassedToService`: `ec2.amazonaws.com`, `ec2.amazonaws.com.cn`
**Justification**: Required to attach IAM roles to EC2 instances for node functionality. Nodes need IAM permissions to interact with AWS services and join the cluster.

**Security**: PassRole is limited to EC2 service only, preventing privilege escalation to other services.

### ManageInstanceProfiles

**Actions**: `iam:AddRoleToInstanceProfile`, `iam:RemoveRoleFromInstanceProfile`, `iam:DeleteInstanceProfile`, `iam:GetInstanceProfile`
**Resource**: `arn:aws:iam::*:instance-profile/rosa-service-managed-*`, `arn:aws:iam::*:instance-profile/*-worker`
**Justification**: Karpenter Controller needs to attach, detach, and remove roles on existing instance profiles and read profile metadata for node provisioning. These operations are scoped by **resource ARN** (no request-tag condition): the profile must already exist and match the allowed name patterns. `rosa-service-managed-*` matches the HCP installer instance profile pattern; `*-worker` covers HyperShift worker-style profile names used in this flow.

**Security**: Service boundary enforced through resource ARN restriction. Only instance profiles matching these naming patterns can be read or modified.

### CreateInstanceProfiles

**Actions**: `iam:CreateInstanceProfile`, `iam:TagInstanceProfile`
**Resource**: `arn:aws:iam::*:instance-profile/rosa-service-managed-*`, `arn:aws:iam::*:instance-profile/*-worker`
**Condition**: `aws:RequestTag/red-hat-managed: "true"`
**Justification**: Same pattern as `sts_hcp_installer_permission_policy.json`: new instance profiles must be created/tagged with the ROSA management tag on the **request**. Platform tags from `HostedControlPlane.spec.platform.aws.resourceTags` (including `red-hat-managed`) flow into the guest `EC2NodeClass` and into the provider’s IAM calls when supported. **Operational validation**: use CloudTrail to confirm `requestParameters` include the expected tags on `CreateInstanceProfile` / `TagInstanceProfile` for the controller role.

**Security**: Service boundary enforced through resource ARN restriction plus required `red-hat-managed` request tag on create/tag calls (aligned with HCP installer policy).

### ListInstanceProfiles

**Actions**: `iam:ListInstanceProfiles`
**Resource**: `*`
**Justification**: Required to discover existing instance profiles for reuse and validation.

**Security**: Read-only list operation poses minimal security risk.

### InterruptionQueueActions

**Actions**: `sqs:DeleteMessage`, `sqs:GetQueueUrl`, `sqs:ReceiveMessage`
**Resource**: `*`
**Justification**: Enables Karpenter Controller to respond to EC2 spot instance interruption notifications and scheduled maintenance events for graceful node draining and replacement. Customers are expected to create and configure the SQS queues for interruption handling.

**Security**: Read and message consumption operations on customer-managed SQS queues. No queue creation or configuration permissions granted.

## Integration with Existing ROSA Services

This policy is designed to complement existing ROSA managed policies:

- **ROSAKubeControllerPolicy**: Handles load balancer and security group management
- **ROSANodePoolManagementPolicy**: Manages static node pools and instance lifecycle
- **ROSAInstallerPolicy**: Handles cluster installation and initial configuration

The Karpenter Controller policy focuses specifically on dynamic, automatic node provisioning while maintaining consistency with ROSA's security patterns and service boundaries.

## Operational Context

ROSA Karpenter Controller operates as a cluster component with the following workflow:
1. Monitors cluster resource demands and node availability
2. Makes provisioning decisions based on workload requirements
3. Creates EC2 instances using standardized launch templates
4. Configures instances with appropriate IAM roles and tagging
5. Integrates nodes into the cluster through standard Kubernetes mechanisms
6. Handles scaling down and resource cleanup when demand decreases
7. Responds to interruption events for graceful node replacement

EC2 lifecycle and tagging use `red-hat-managed` (request and/or resource conditions) as the primary service boundary where those statements apply; IAM instance profile **create/tag** uses **ARN patterns** plus **`aws:RequestTag/red-hat-managed`**, consistent with the HCP installer managed policy.