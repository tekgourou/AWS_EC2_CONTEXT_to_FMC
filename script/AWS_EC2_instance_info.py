from collections import defaultdict
import boto3

def get_aws_ec2_info():
    # Connect to EC2
    ec2 = boto3.resource('ec2')
    ec2_client = boto3.client('ec2')
    # Create a image description list
    image_description_list = ec2_client.describe_images()

    # Get information for all running instances
    running_instances = ec2.instances.filter(Filters=[{
        'Name': 'instance-state-name',
        'Values': ['running']}])
    ec2info = defaultdict()
    instances = []
    for instance in running_instances:
        for tag in instance.tags:
            if 'Name'in tag['Key']:
                name = tag['Value']
        # Add instance info to a dictionary
        ec2info[instance.id] = {
            'Name': name,
            'Type': instance.instance_type,
            'VPC ID': instance.vpc_id,
            'Private IP': instance.private_ip_address,
            'Public IP': instance.public_ip_address,
            'Image Id': instance.image_id,
            }

        attributes = ['Name', 'Type', 'VPC ID', 'Private IP', 'Public IP', 'Image Id']
        for instance_id, instance in ec2info.items():
            for key, value in sorted(image_description_list.items()):
                for links in value:
                    try:
                        for key2, value2 in sorted(links.items()):
                            if value2 == instance['Image Id'] :
                                description = links['Description']
                                if links['Description'].startswith('['):
                                    description = description.split("]")[1]
                                    #print('OS Description: {}'.format(description))
                                instance['Image Description'] = description.replace(',', '')
                    except:
                        pass
        instances.append(instance)

    return instances

#instances_list = get_aws_ec2_info()
#print(instances_list)
