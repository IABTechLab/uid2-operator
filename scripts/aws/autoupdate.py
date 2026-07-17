#!/usr/bin/env python3
"""
EC2 AMI Update Script

This script:
1. Queries EC2 metadata to get instance information
2. Finds the Auto Scaling Group containing this instance
3. Updates the launch template with a new AMI ID
4. Triggers an instance refresh
"""

import boto3
import requests
import json
import time
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EC2AMIUpdater:
    def __init__(self, new_ami_id='ami-123123123'):
        self.new_ami_id = new_ami_id
        self.instance_id = None
        self.region = None
        self.asg_name = None
        self.launch_template_id = None
        self.launch_template_name = None
        
        # Initialize AWS clients (will be set after getting region)
        self.ec2_client = None
        self.autoscaling_client = None
        
    def get_imds_token(self):
        """Get IMDSv2 token for secure metadata access"""
        try:
            response = requests.put(
                'http://169.254.169.254/latest/api/token',
                headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
                timeout=5
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Failed to get IMDSv2 token: {e}")
            return None
    
    def get_instance_metadata(self):
        """Query EC2 metadata to get instance information (supports both IMDSv1 and IMDSv2)"""
        try:
            # First try to get IMDSv2 token
            token = self.get_imds_token()
            headers = {}
            if token:
                headers['X-aws-ec2-metadata-token'] = token
                logger.info("Using IMDSv2 for metadata access")
            else:
                logger.info("Falling back to IMDSv1 for metadata access")
            
            # Get instance ID
            response = requests.get(
                'http://169.254.169.254/latest/meta-data/instance-id', 
                headers=headers, 
                timeout=5
            )
            response.raise_for_status()
            self.instance_id = response.text
            logger.info(f"Instance ID: {self.instance_id}")
            
            # Get region
            response = requests.get(
                'http://169.254.169.254/latest/meta-data/placement/region', 
                headers=headers, 
                timeout=5
            )
            response.raise_for_status()
            self.region = response.text
            logger.info(f"Region: {self.region}")
            
            # Initialize AWS clients now that we have the region
            self.ec2_client = boto3.client('ec2', region_name=self.region)
            self.autoscaling_client = boto3.client('autoscaling', region_name=self.region)
            
            return True
            
        except requests.RequestException as e:
            logger.error(f"Failed to query EC2 metadata: {e}")
            return False
        except Exception as e:
            logger.error(f"Error initializing AWS clients: {e}")
            return False
    
    def find_auto_scaling_group(self):
        """Find the Auto Scaling Group that contains this instance"""
        try:
            response = self.autoscaling_client.describe_auto_scaling_instances(
                InstanceIds=[self.instance_id]
            )
            
            if not response['AutoScalingInstances']:
                logger.error(f"Instance {self.instance_id} is not part of an Auto Scaling Group")
                return False
                
            self.asg_name = response['AutoScalingInstances'][0]['AutoScalingGroupName']
            logger.info(f"Found Auto Scaling Group: {self.asg_name}")
            return True
            
        except ClientError as e:
            logger.error(f"Error finding Auto Scaling Group: {e}")
            return False
    
    def get_launch_template_info(self):
        """Get launch template information from the Auto Scaling Group"""
        try:
            response = self.autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[self.asg_name]
            )
            
            if not response['AutoScalingGroups']:
                logger.error(f"Auto Scaling Group {self.asg_name} not found")
                return False
                
            asg = response['AutoScalingGroups'][0]
            
            # Check if ASG uses launch template
            if 'LaunchTemplate' in asg:
                launch_template = asg['LaunchTemplate']
                self.launch_template_id = launch_template.get('LaunchTemplateId')
                self.launch_template_name = launch_template.get('LaunchTemplateName')
                logger.info(f"Launch Template ID: {self.launch_template_id}")
                logger.info(f"Launch Template Name: {self.launch_template_name}")
                return True
            else:
                logger.error("Auto Scaling Group does not use a launch template")
                return False
                
        except ClientError as e:
            logger.error(f"Error getting launch template info: {e}")
            return False
    
    def update_launch_template(self):
        """Update the launch template with the new AMI ID"""
        try:
            # Get current launch template version
            response = self.ec2_client.describe_launch_template_versions(
                LaunchTemplateId=self.launch_template_id,
                Versions=['$Latest']
            )
            
            if not response['LaunchTemplateVersions']:
                logger.error("No launch template versions found")
                return False
                
            current_version = response['LaunchTemplateVersions'][0]
            current_ami_id = current_version['LaunchTemplateData'].get('ImageId')
            logger.info(f"Current AMI ID: {current_ami_id}")
            
            # Check if AMI ID is already up to date
            if current_ami_id == self.new_ami_id:
                logger.info("AMI ID is already up to date")
            
            # Create new launch template version with updated AMI ID
            launch_template_data = current_version['LaunchTemplateData'].copy()
            launch_template_data['ImageId'] = self.new_ami_id
            
            response = self.ec2_client.create_launch_template_version(
                LaunchTemplateId=self.launch_template_id,
                LaunchTemplateData=launch_template_data,
                SourceVersion=str(current_version['VersionNumber'])
            )
            
            new_version = response['LaunchTemplateVersion']['VersionNumber']
            logger.info(f"Created new launch template version: {new_version}")
            
            # Update ASG to use the new launch template version
            logger.info(f"Updating ASG {self.asg_name} to use launch template version {new_version}")
            self.autoscaling_client.update_auto_scaling_group(
                AutoScalingGroupName=self.asg_name,
                LaunchTemplate={
                    'LaunchTemplateId': self.launch_template_id,
                    'Version': str(new_version)
                }
            )
            
            logger.info(f"Updated Auto Scaling Group {self.asg_name} to use launch template version {new_version}")
            return True
            
        except ClientError as e:
            logger.error(f"Error updating launch template: {e}")
            return False
    
    def trigger_instance_refresh(self):
        """Trigger an instance refresh for the Auto Scaling Group"""
        try:
            response = self.autoscaling_client.start_instance_refresh(
                AutoScalingGroupName=self.asg_name,
                Strategy='Rolling',
                Preferences={
                    'InstanceWarmup': 300,
                    'MinHealthyPercentage': 50
                }
            )
            
            instance_refresh_id = response['InstanceRefreshId']
            logger.info(f"Started instance refresh: {instance_refresh_id}")
            
            # Monitor the instance refresh progress
            self.monitor_instance_refresh(instance_refresh_id)
            
            return True
            
        except ClientError as e:
            logger.error(f"Error triggering instance refresh: {e}")
            return False
    
    def monitor_instance_refresh(self, instance_refresh_id):
        """Monitor the instance refresh progress"""
        logger.info("Monitoring instance refresh progress...")
        
        while True:
            try:
                response = self.autoscaling_client.describe_instance_refreshes(
                    AutoScalingGroupName=self.asg_name,
                    InstanceRefreshIds=[instance_refresh_id]
                )
                
                if not response['InstanceRefreshes']:
                    logger.error("Instance refresh not found")
                    break
                    
                refresh = response['InstanceRefreshes'][0]
                status = refresh['Status']
                percentage = refresh.get('PercentageComplete', 0)
                
                logger.info(f"Instance refresh status: {status} ({percentage}% complete)")
                
                if status in ['Successful', 'Failed', 'Cancelled']:
                    break
                    
                time.sleep(30)  # Wait 30 seconds before checking again
                
            except ClientError as e:
                logger.error(f"Error monitoring instance refresh: {e}")
                break
    
    def run(self):
        """Run the complete AMI update process"""
        logger.info("Starting EC2 AMI update process...")
        
        # Step 1: Get instance metadata
        if not self.get_instance_metadata():
            logger.error("Failed to get instance metadata")
            return False
            
        # Step 2: Find Auto Scaling Group
        if not self.find_auto_scaling_group():
            logger.error("Failed to find Auto Scaling Group")
            return False
            
        # Step 3: Get launch template info
        if not self.get_launch_template_info():
            logger.error("Failed to get launch template info")
            return False
            
        # Step 4: Update launch template
        if not self.update_launch_template():
            logger.error("Failed to update launch template")
            return False
            
        # Step 5: Trigger instance refresh
        if not self.trigger_instance_refresh():
            logger.error("Failed to trigger instance refresh")
            return False
            
        logger.info("EC2 AMI update process completed successfully!")
        return True

def get_latest_ami_id():
    """Fetch the latest AMI ID from the releases.json file"""
    try:
        # Fetch the releases.json from the GitHub repository
        response = requests.get(
            'https://raw.githubusercontent.com/UnifiedID2/uid2-docs-preview/main/releases.json',
            timeout=10
        )
        response.raise_for_status()
        
        # Parse the JSON response
        releases_data = response.json()
        
        # Extract the first AMI ID from aws.us-east-1 array
        ami_ids = releases_data.get('aws', {}).get('us-east-1', [])
        
        if not ami_ids:
            logger.error("No AMI IDs found in releases.json")
            return None
            
        latest_ami_id = ami_ids[0]
        logger.info(f"Latest AMI ID from releases.json: {latest_ami_id}")
        return latest_ami_id
        
    except requests.RequestException as e:
        logger.error(f"Failed to fetch releases.json: {e}")
        return None
    except (KeyError, IndexError, ValueError) as e:
        logger.error(f"Failed to parse releases.json: {e}")
        return None

def main():
    """Main function"""
    # Fetch the latest AMI ID from releases.json
    ami_id = get_latest_ami_id()
    
    if ami_id is None:
        logger.error("Failed to get latest AMI ID")
        print("AMI update failed! Could not fetch latest AMI ID from releases.json")
        return 1
    
    updater = EC2AMIUpdater(new_ami_id=ami_id)
    
    if updater.run():
        print(f"AMI update completed successfully! {ami_id} has been installed.")
        return 0
    else:
        print("AMI update failed!")
        return 1

if __name__ == '__main__':
    exit(main()) 