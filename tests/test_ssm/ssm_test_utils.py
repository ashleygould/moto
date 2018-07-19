from __future__ import unicode_literals

import sure   # noqa
import datetime
import hashlib
import json

from moto.ssm.models import FAKE_ACCOUNT_ID

MOCK_SSM_DOCUMENT = json.dumps(dict(
    schemaVersion='2.2',
    description='Mock SSM Document',
    parameters=dict(),
    mainSteps=[
        dict(
            action='aws:runShellScript',
            name='AWS-RunShellScript',
            inputs=dict(
                runCommandand=[
                    'echo "hello world',
                ]
            )
        )
    ]
))

def validate_ssm_document(response):
    doc = response['DocumentDescription']
    doc['Hash'].should.equal(hashlib.sha256(MOCK_SSM_DOCUMENT.encode()).hexdigest())
    doc['HashType'].should.equal('Sha256')
    doc['Name'].should.equal('AWS-RunShellScript')
    doc['Owner'].should.equal(FAKE_ACCOUNT_ID)
    doc['CreatedDate'].should.be.a(datetime.datetime)
    doc['Status'].should.equal('Active')
    doc['DocumentVersion'].should.equal('1')
    doc['Description'].should.equal('Mock SSM Document')
    doc['Parameters'].should.be.a(list)
    doc['PlatformTypes'].should.be.a(list)
    doc['PlatformTypes'][0].should.equal('Linux')
    doc['DocumentType'].should.equal('Command')
    doc['SchemaVersion'].should.equal('2.2')
    doc['LatestVersion'].should.equal('1')
    doc['DefaultVersion'].should.equal('1')
    doc['DocumentFormat'].should.equal('JSON')
    doc['TargetType'].should.equal('/AWS::EC2::Instance')
    doc['Tags'].should.be.a(list)
    #assert False

"""
{
    "Document": {
        "Hash": "5266528174f8987024c43a820d0d1f16d5905f68945397765ac4ff3023e7a0df",
        "HashType": "Sha256",
        "Name": "sshPubkeySetup",
        "Owner": "071826132890",
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

