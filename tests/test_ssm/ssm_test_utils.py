from __future__ import unicode_literals

import sure   # noqa
import datetime
import hashlib
import json
import yaml
import six

from moto.ssm.models import FAKE_ACCOUNT_ID

MOCK_SSM_DOCUMENT = dict(
    schemaVersion='2.2',
    description='Mock SSM Document',
    parameters=dict(),
    mainSteps=[
        dict(
            action='aws:runShellScript',
            name='RunMockShellScript',
            inputs=dict(
                runCommandand=[
                    'echo "hello world',
                ]
            )
        )
    ]
)


def validate_document_listing(doc, content):
    doc['Name'].should.be.a(six.string_types)
    doc['Owner'].should.equal(FAKE_ACCOUNT_ID)
    doc['DocumentVersion'].should.match(r'[1-9][0-9]*')
    doc['PlatformTypes'].should.be.a(list)
    for platform_type in doc['PlatformTypes']:
        platform_type.should.be.within(['Linux', 'Windows'])
    doc['DocumentType'].should.be.within(['Command', 'Policy', 'Automation'])
    doc['SchemaVersion'].should.equal(content['schemaVersion'])
    doc['DocumentFormat'].should.be.within(['JSON', 'YAML'])
    if 'TargetType' in doc:
        doc['TargetType'].should.match(r'\/[\w\.\-\:\/]*')
    doc['Tags'].should.be.a(list)


def validate_document_hash(doc, content):
    if doc['DocumentFormat'] == 'JSON':
        content = json.dumps(content)
    else:
        content = yaml.dump(content)
    doc['Hash'].should.equal(hashlib.sha256(content.encode()).hexdigest())

    
def validate_document_description(doc, content):
    validate_document_hash(doc, content)
    validate_document_listing(doc, content)
    doc['HashType'].should.equal('Sha256')
    doc['CreatedDate'].should.be.a(datetime.datetime)
    doc['Status'].should.equal('Active')
    doc['Description'].should.equal(content['description'])
    doc['Parameters'].should.be.a(list)
    doc['LatestVersion'].should.match(r'[1-9][0-9]*')
    doc['DefaultVersion'].should.match(r'[1-9][0-9]*')


"""
{
    'DocumentIdentifiers': [
        {
            'Name': 'string',
            'Owner': 'string',
            'PlatformTypes': [
                'Windows'|'Linux',
            ],
            'DocumentVersion': 'string',
            'DocumentType': 'Command'|'Policy'|'Automation',
            'SchemaVersion': 'string',
            'DocumentFormat': 'YAML'|'JSON',
            'TargetType': 'string',
            'Tags': [
                {
                    'Key': 'string',
                    'Value': 'string'
                },
            ]
        },
    ],
    'NextToken': 'string'
}
"""

"""
{
    "Document": {
        "Hash": "5266528174f8987024c43a820d0d1f16d5905f68945397765ac4ff3023e7a0df",
        "HashType": "Sha256",
        "Name": "sshPubkeySetup",
        "Owner": "XXXXXXXXXXXXXXXX",
        "CreatedDate": 1531949537.294,
        "Status": "Active",
        "DocumentVersion": "1",
        "Description": "Install ssh public key into ~ec2-user/.ssh/authorized_keys",
        "Parameters": [],
        "PlatformTypes": [
            "Linux"
        ],
        "DocumentType": "Command",
        "SchemaVersion": "2.2",
        "LatestVersion": "1",
        "DefaultVersion": "1",
        "DocumentFormat": "YAML",
        "TargetType": "/AWS::EC2::Instance",
        "Tags": []
    }
}
"""
