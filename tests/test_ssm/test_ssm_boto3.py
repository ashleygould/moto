from __future__ import unicode_literals

import boto3
import botocore.exceptions
import sure   # noqa
import datetime
import uuid
import json
import yaml
import hashlib

from botocore.exceptions import ClientError
from nose.tools import assert_raises

from moto import mock_ssm
from .ssm_test_utils import (
    MOCK_SSM_DOCUMENT,
    validate_document_hash,
    validate_document_description,
    validate_document_listing,
    setup_document_version_mock_env,
)


@mock_ssm
def test_delete_parameter():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='String')

    response = client.get_parameters(Names=['test'])
    len(response['Parameters']).should.equal(1)

    client.delete_parameter(Name='test')

    response = client.get_parameters(Names=['test'])
    len(response['Parameters']).should.equal(0)


@mock_ssm
def test_delete_parameters():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='String')

    response = client.get_parameters(Names=['test'])
    len(response['Parameters']).should.equal(1)

    result = client.delete_parameters(Names=['test', 'invalid'])
    len(result['DeletedParameters']).should.equal(1)
    len(result['InvalidParameters']).should.equal(1)

    response = client.get_parameters(Names=['test'])
    len(response['Parameters']).should.equal(0)


@mock_ssm
def test_get_parameters_by_path():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='/foo/name1',
        Description='A test parameter',
        Value='value1',
        Type='String')

    client.put_parameter(
        Name='/foo/name2',
        Description='A test parameter',
        Value='value2',
        Type='String')

    client.put_parameter(
        Name='/bar/name3',
        Description='A test parameter',
        Value='value3',
        Type='String')

    client.put_parameter(
        Name='/bar/name3/name4',
        Description='A test parameter',
        Value='value4',
        Type='String')

    client.put_parameter(
        Name='/baz/name1',
        Description='A test parameter (list)',
        Value='value1,value2,value3',
        Type='StringList')

    client.put_parameter(
        Name='/baz/name2',
        Description='A test parameter',
        Value='value1',
        Type='String')

    client.put_parameter(
        Name='/baz/pwd',
        Description='A secure test parameter',
        Value='my_secret',
        Type='SecureString',
        KeyId='alias/aws/ssm')

    client.put_parameter(
        Name='foo',
        Description='A test parameter',
        Value='bar',
        Type='String')

    client.put_parameter(
        Name='baz',
        Description='A test parameter',
        Value='qux',
        Type='String')

    response = client.get_parameters_by_path(Path='/', Recursive=False)
    len(response['Parameters']).should.equal(2)
    {p['Value'] for p in response['Parameters']}.should.equal(
        set(['bar', 'qux'])
    )

    response = client.get_parameters_by_path(Path='/', Recursive=True)
    len(response['Parameters']).should.equal(9)

    response = client.get_parameters_by_path(Path='/foo')
    len(response['Parameters']).should.equal(2)
    {p['Value'] for p in response['Parameters']}.should.equal(
        set(['value1', 'value2'])
    )

    response = client.get_parameters_by_path(Path='/bar', Recursive=False)
    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Value'].should.equal('value3')

    response = client.get_parameters_by_path(Path='/bar', Recursive=True)
    len(response['Parameters']).should.equal(2)
    {p['Value'] for p in response['Parameters']}.should.equal(
        set(['value3', 'value4'])
    )

    response = client.get_parameters_by_path(Path='/baz')
    len(response['Parameters']).should.equal(3)

    filters = [{
        'Key': 'Type',
        'Option': 'Equals',
        'Values': ['StringList'],
    }]
    response = client.get_parameters_by_path(Path='/baz', ParameterFilters=filters)
    len(response['Parameters']).should.equal(1)
    {p['Name'] for p in response['Parameters']}.should.equal(
        set(['/baz/name1'])
    )

    # note: 'Option' is optional (default: 'Equals')
    filters = [{
        'Key': 'Type',
        'Values': ['StringList'],
    }]
    response = client.get_parameters_by_path(Path='/baz', ParameterFilters=filters)
    len(response['Parameters']).should.equal(1)
    {p['Name'] for p in response['Parameters']}.should.equal(
        set(['/baz/name1'])
    )

    filters = [{
        'Key': 'Type',
        'Option': 'Equals',
        'Values': ['String'],
    }]
    response = client.get_parameters_by_path(Path='/baz', ParameterFilters=filters)
    len(response['Parameters']).should.equal(1)
    {p['Name'] for p in response['Parameters']}.should.equal(
        set(['/baz/name2'])
    )

    filters = [{
        'Key': 'Type',
        'Option': 'Equals',
        'Values': ['String', 'SecureString'],
    }]
    response = client.get_parameters_by_path(Path='/baz', ParameterFilters=filters)
    len(response['Parameters']).should.equal(2)
    {p['Name'] for p in response['Parameters']}.should.equal(
        set(['/baz/name2', '/baz/pwd'])
    )

    filters = [{
        'Key': 'Type',
        'Option': 'BeginsWith',
        'Values': ['String'],
    }]
    response = client.get_parameters_by_path(Path='/baz', ParameterFilters=filters)
    len(response['Parameters']).should.equal(2)
    {p['Name'] for p in response['Parameters']}.should.equal(
        set(['/baz/name1', '/baz/name2'])
    )

    filters = [{
        'Key': 'KeyId',
        'Option': 'Equals',
        'Values': ['alias/aws/ssm'],
    }]
    response = client.get_parameters_by_path(Path='/baz', ParameterFilters=filters)
    len(response['Parameters']).should.equal(1)
    {p['Name'] for p in response['Parameters']}.should.equal(
        set(['/baz/pwd'])
    )


@mock_ssm
def test_put_parameter():
    client = boto3.client('ssm', region_name='us-east-1')

    response = client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='String')

    response['Version'].should.equal(1)

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=False)

    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('value')
    response['Parameters'][0]['Type'].should.equal('String')
    response['Parameters'][0]['Version'].should.equal(1)

    try:
        client.put_parameter(
            Name='test',
            Description='desc 2',
            Value='value 2',
            Type='String')
        raise RuntimeError('Should fail')
    except botocore.exceptions.ClientError as err:
        err.operation_name.should.equal('PutParameter')
        err.response['Error']['Message'].should.equal('Parameter test already exists.')

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=False)

    # without overwrite nothing change
    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('value')
    response['Parameters'][0]['Type'].should.equal('String')
    response['Parameters'][0]['Version'].should.equal(1)

    response = client.put_parameter(
        Name='test',
        Description='desc 3',
        Value='value 3',
        Type='String',
        Overwrite=True)

    response['Version'].should.equal(2)

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=False)

    # without overwrite nothing change
    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('value 3')
    response['Parameters'][0]['Type'].should.equal('String')
    response['Parameters'][0]['Version'].should.equal(2)


@mock_ssm
def test_get_parameter():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='String')

    response = client.get_parameter(
        Name='test',
        WithDecryption=False)

    response['Parameter']['Name'].should.equal('test')
    response['Parameter']['Value'].should.equal('value')
    response['Parameter']['Type'].should.equal('String')


@mock_ssm
def test_get_nonexistant_parameter():
    client = boto3.client('ssm', region_name='us-east-1')

    try:
        client.get_parameter(
            Name='test_noexist',
            WithDecryption=False)
        raise RuntimeError('Should of failed')
    except botocore.exceptions.ClientError as err:
        err.operation_name.should.equal('GetParameter')
        err.response['Error']['Message'].should.equal('Parameter test_noexist not found.')


@mock_ssm
def test_describe_parameters():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='String')

    response = client.describe_parameters()

    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Type'].should.equal('String')


@mock_ssm
def test_describe_parameters_paging():
    client = boto3.client('ssm', region_name='us-east-1')

    for i in range(50):
        client.put_parameter(
            Name="param-%d" % i,
            Value="value-%d" % i,
            Type="String"
        )

    response = client.describe_parameters()
    len(response['Parameters']).should.equal(10)
    response['NextToken'].should.equal('10')

    response = client.describe_parameters(NextToken=response['NextToken'])
    len(response['Parameters']).should.equal(10)
    response['NextToken'].should.equal('20')

    response = client.describe_parameters(NextToken=response['NextToken'])
    len(response['Parameters']).should.equal(10)
    response['NextToken'].should.equal('30')

    response = client.describe_parameters(NextToken=response['NextToken'])
    len(response['Parameters']).should.equal(10)
    response['NextToken'].should.equal('40')

    response = client.describe_parameters(NextToken=response['NextToken'])
    len(response['Parameters']).should.equal(10)
    response['NextToken'].should.equal('50')

    response = client.describe_parameters(NextToken=response['NextToken'])
    len(response['Parameters']).should.equal(0)
    ''.should.equal(response.get('NextToken', ''))


@mock_ssm
def test_describe_parameters_filter_names():
    client = boto3.client('ssm', region_name='us-east-1')

    for i in range(50):
        p = {
            'Name': "param-%d" % i,
            'Value': "value-%d" % i,
            'Type': "String"
        }
        if i % 5 == 0:
            p['Type'] = 'SecureString'
            p['KeyId'] = 'a key'
        client.put_parameter(**p)

    response = client.describe_parameters(Filters=[
        {
            'Key': 'Name',
            'Values': ['param-22']
        },
    ])
    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('param-22')
    response['Parameters'][0]['Type'].should.equal('String')
    ''.should.equal(response.get('NextToken', ''))


@mock_ssm
def test_describe_parameters_filter_type():
    client = boto3.client('ssm', region_name='us-east-1')

    for i in range(50):
        p = {
            'Name': "param-%d" % i,
            'Value': "value-%d" % i,
            'Type': "String"
        }
        if i % 5 == 0:
            p['Type'] = 'SecureString'
            p['KeyId'] = 'a key'
        client.put_parameter(**p)

    response = client.describe_parameters(Filters=[
        {
            'Key': 'Type',
            'Values': ['SecureString']
        },
    ])
    len(response['Parameters']).should.equal(10)
    response['Parameters'][0]['Type'].should.equal('SecureString')
    '10'.should.equal(response.get('NextToken', ''))


@mock_ssm
def test_describe_parameters_filter_keyid():
    client = boto3.client('ssm', region_name='us-east-1')

    for i in range(50):
        p = {
            'Name': "param-%d" % i,
            'Value': "value-%d" % i,
            'Type': "String"
        }
        if i % 5 == 0:
            p['Type'] = 'SecureString'
            p['KeyId'] = "key:%d" % i
        client.put_parameter(**p)

    response = client.describe_parameters(Filters=[
        {
            'Key': 'KeyId',
            'Values': ['key:10']
        },
    ])
    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('param-10')
    response['Parameters'][0]['Type'].should.equal('SecureString')
    ''.should.equal(response.get('NextToken', ''))


@mock_ssm
def test_describe_parameters_attributes():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='aa',
        Value='11',
        Type='String',
        Description='my description'
    )

    client.put_parameter(
        Name='bb',
        Value='22',
        Type='String'
    )

    response = client.describe_parameters()
    len(response['Parameters']).should.equal(2)

    response['Parameters'][0]['Description'].should.equal('my description')
    response['Parameters'][0]['Version'].should.equal(1)
    response['Parameters'][0]['LastModifiedDate'].should.be.a(datetime.date)
    response['Parameters'][0]['LastModifiedUser'].should.equal('N/A')

    response['Parameters'][1].get('Description').should.be.none
    response['Parameters'][1]['Version'].should.equal(1)


@mock_ssm
def test_get_parameter_invalid():
    client = client = boto3.client('ssm', region_name='us-east-1')
    response = client.get_parameters(
        Names=[
            'invalid'
        ],
        WithDecryption=False)

    len(response['Parameters']).should.equal(0)
    len(response['InvalidParameters']).should.equal(1)
    response['InvalidParameters'][0].should.equal('invalid')


@mock_ssm
def test_put_parameter_secure_default_kms():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='SecureString')

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=False)

    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('kms:default:value')
    response['Parameters'][0]['Type'].should.equal('SecureString')

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=True)

    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('value')
    response['Parameters'][0]['Type'].should.equal('SecureString')


@mock_ssm
def test_put_parameter_secure_custom_kms():
    client = boto3.client('ssm', region_name='us-east-1')

    client.put_parameter(
        Name='test',
        Description='A test parameter',
        Value='value',
        Type='SecureString',
        KeyId='foo')

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=False)

    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('kms:foo:value')
    response['Parameters'][0]['Type'].should.equal('SecureString')

    response = client.get_parameters(
        Names=[
            'test'
        ],
        WithDecryption=True)

    len(response['Parameters']).should.equal(1)
    response['Parameters'][0]['Name'].should.equal('test')
    response['Parameters'][0]['Value'].should.equal('value')
    response['Parameters'][0]['Type'].should.equal('SecureString')


@mock_ssm
def test_add_remove_list_tags_for_resource():
    client = boto3.client('ssm', region_name='us-east-1')

    client.add_tags_to_resource(
        ResourceId='test',
        ResourceType='Parameter',
        Tags=[{'Key': 'test-key', 'Value': 'test-value'}]
    )

    response = client.list_tags_for_resource(
        ResourceId='test',
        ResourceType='Parameter'
    )
    len(response['TagList']).should.equal(1)
    response['TagList'][0]['Key'].should.equal('test-key')
    response['TagList'][0]['Value'].should.equal('test-value')

    client.remove_tags_from_resource(
        ResourceId='test',
        ResourceType='Parameter',
        TagKeys=['test-key']
    )

    response = client.list_tags_for_resource(
        ResourceId='test',
        ResourceType='Parameter'
    )
    len(response['TagList']).should.equal(0)


@mock_ssm
def test_send_command():
    ssm_document = 'MockSSMDocument'
    params = {'commands': ['#!/bin/bash\necho \'hello world\'']}

    client = boto3.client('ssm', region_name='us-east-1')
    # note the timeout is determined server side, so this is a simpler check.
    before = datetime.datetime.now()

    response = client.send_command(
        InstanceIds=['i-123456'],
        DocumentName=ssm_document,
        Parameters=params,
        OutputS3Region='us-east-2',
        OutputS3BucketName='the-bucket',
        OutputS3KeyPrefix='pref'
    )
    cmd = response['Command']

    cmd['CommandId'].should_not.be(None)
    cmd['DocumentName'].should.equal(ssm_document)
    cmd['Parameters'].should.equal(params)

    cmd['OutputS3Region'].should.equal('us-east-2')
    cmd['OutputS3BucketName'].should.equal('the-bucket')
    cmd['OutputS3KeyPrefix'].should.equal('pref')

    cmd['ExpiresAfter'].should.be.greater_than(before)

    # test sending a command without any optional parameters
    response = client.send_command(
        DocumentName=ssm_document)

    cmd = response['Command']

    cmd['CommandId'].should_not.be(None)
    cmd['DocumentName'].should.equal(ssm_document)


@mock_ssm
def test_list_commands():
    client = boto3.client('ssm', region_name='us-east-1')

    ssm_document = 'MockSSMDocument'
    params = {'commands': ['#!/bin/bash\necho \'hello world\'']}

    response = client.send_command(
        InstanceIds=['i-123456'],
        DocumentName=ssm_document,
        Parameters=params,
        OutputS3Region='us-east-2',
        OutputS3BucketName='the-bucket',
        OutputS3KeyPrefix='pref')

    cmd = response['Command']
    cmd_id = cmd['CommandId']

    # get the command by id
    response = client.list_commands(
        CommandId=cmd_id)

    cmds = response['Commands']
    len(cmds).should.equal(1)
    cmds[0]['CommandId'].should.equal(cmd_id)

    # add another command with the same instance id to test listing by
    # instance id
    client.send_command(
        InstanceIds=['i-123456'],
        DocumentName=ssm_document)

    response = client.list_commands(
        InstanceId='i-123456')

    cmds = response['Commands']
    len(cmds).should.equal(2)

    for cmd in cmds:
        cmd['InstanceIds'].should.contain('i-123456')

    # test the error case for an invalid command id
    with assert_raises(ClientError):
        response = client.list_commands(
            CommandId=str(uuid.uuid4()))


# SSM Documents Support


@mock_ssm
def test_create_document():
    client = boto3.client('ssm', region_name='us-east-1')

    # JSON format
    response = client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument',
        DocumentType='Command',
        DocumentFormat='JSON',
        TargetType='/AWS::EC2::Instance',
    )
    response.should.have.key('DocumentDescription')
    doc = response['DocumentDescription']
    validate_document_description(doc, MOCK_SSM_DOCUMENT)
    doc['Name'].should.equal('MockSSMDocument')
    doc['DocumentType'].should.equal('Command')
    doc['DocumentFormat'].should.equal('JSON')
    doc['TargetType'].should.equal('/AWS::EC2::Instance')
    doc['DocumentVersion'].should.equal('1')
    doc['LatestVersion'].should.equal('1')
    doc['DefaultVersion'].should.equal('1')

    # YAML format
    response = client.create_document(
        Content=yaml.dump(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument',
        DocumentFormat='YAML',
        TargetType='/',
    )
    response.should.have.key('DocumentDescription')
    doc = response['DocumentDescription']
    validate_document_description(doc, MOCK_SSM_DOCUMENT)
    doc['DocumentFormat'].should.equal('YAML')
    doc['TargetType'].should.equal('/')


@mock_ssm
def test_describe_document():
    tag_list = [
        {'Key': 'test-key1', 'Value': 'test-value1'},
        {'Key': 'test-key2', 'Value': 'test-value2'},
    ]
    content = MOCK_SSM_DOCUMENT
    client = boto3.client('ssm', region_name='us-east-1')
    client.create_document(
        Content=json.dumps(content),
        Name='MockSSMDocument',
        DocumentType='Command',
        DocumentFormat='JSON',
        TargetType='/AWS::EC2::Instance',
    )
    client.add_tags_to_resource(
        ResourceId='MockSSMDocument',
        ResourceType='Document',
        Tags=tag_list,
    )
    response = client.describe_document(
        Name='MockSSMDocument',
        DocumentVersion='1',
    )
    response.should.have.key('Document')
    doc = response['Document']
    validate_document_description(doc, content)
    sorted(doc['Tags']).should.equal(sorted(tag_list))


@mock_ssm
def test_list_documents():
    client = boto3.client('ssm', region_name='us-east-1')
    client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument-01',
    )
    client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument-02',
    )
    client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument-03',
    )
    response = client.list_documents()
    response.should.have.key('DocumentIdentifiers')
    for doc in response['DocumentIdentifiers']:
        validate_document_listing(doc, MOCK_SSM_DOCUMENT)


@mock_ssm
def test_delete_document():
    client = boto3.client('ssm', region_name='us-east-1')
    client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument',
    )
    response = client.delete_document(
        Name='MockSSMDocument',
    )
    response.should.be.a(dict)
    response.pop('ResponseMetadata')
    response.should.equal(dict())
    with assert_raises(ClientError):
        response = client.describe_document(
            Name='MockSSMDocument',
        )


@mock_ssm
def test_update_document():
    client = boto3.client('ssm', region_name='us-east-1')
    content = MOCK_SSM_DOCUMENT
    response01 = client.create_document(
        Content=json.dumps(content),
        Name='MockSSMDocument',
    )
    content['description'] = 'An Updated Mock SSM Document'
    response02 = client.update_document(
        Content=json.dumps(content),
        Name='MockSSMDocument',
    )
    response02.should.have.key('DocumentDescription')
    doc = response02['DocumentDescription']
    validate_document_hash(doc, content)
    doc['Name'].should.equal('MockSSMDocument')
    doc['DocumentVersion'].should.equal('2')
    doc['Description'].should.equal('An Updated Mock SSM Document')
    doc['LatestVersion'].should.equal('2')
    doc['DefaultVersion'].should.equal('1')


@mock_ssm
def test_list_document_versions():
    client = boto3.client('ssm', region_name='us-east-1')
    setup_document_version_mock_env(client)
    response = client.list_document_versions(
        Name='MockSSMDocument',
    )
    response.should.have.key('DocumentVersions').should.be.a(list)
    for version in response['DocumentVersions']:
        version['Name'].should.equal('MockSSMDocument')
        version['CreatedDate'].should.be.a(datetime.datetime)
        version['DocumentFormat'].should.be.within(['YAML', 'JSON'])
    response['DocumentVersions'][0]['DocumentVersion'].should.equal('1')
    response['DocumentVersions'][1]['DocumentVersion'].should.equal('2')
    response['DocumentVersions'][0]['IsDefaultVersion'].should.be.true
    response['DocumentVersions'][1]['IsDefaultVersion'].should.be.false


@mock_ssm
def test_update_document_default_version():
    client = boto3.client('ssm', region_name='us-east-1')
    setup_document_version_mock_env(client)
    response = client.update_document_default_version(
        Name='MockSSMDocument',
        DocumentVersion='2'
    )
    response.should.have.key('Description').should.be.a(dict)
    response['Description']['Name'].should.equal('MockSSMDocument')
    response['Description']['DefaultVersion'].should.equal('2')
    response = client.list_document_versions(
        Name='MockSSMDocument',
    )
    response['DocumentVersions'][0]['IsDefaultVersion'].should.be.false
    response['DocumentVersions'][1]['IsDefaultVersion'].should.be.true


@mock_ssm
def test_get_document():
    client = boto3.client('ssm', region_name='us-east-1')
    client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument',
    )
    response = client.get_document(
        Name='MockSSMDocument',
        DocumentVersion='1',
        DocumentFormat='YAML',
    )
    response.should.be.a(dict)
    response['Name'].should.equal('MockSSMDocument')
    response['DocumentVersion'].should.equal('1')
    json.dumps(response['Content']).should.equal(json.dumps(MOCK_SSM_DOCUMENT))
    response['DocumentFormat'].should.be.within(['YAML', 'JSON'])
    response['DocumentType'].should.be.within(['Command', 'Policy', 'Automation'])
