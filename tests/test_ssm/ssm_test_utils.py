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
    #parameters=dict(),
    parameters={
        'param1': {
            'description': 'body parts',
            'type': 'String',
            'allowedValues': ['spleen', 'heart'],
            'default': 'organ',
        },
        'param2': {
            'description': 'body parts',
            'type': 'String',
            'allowedValues': ['spleen', 'heart'],
            'default': 'spleen',
        }
    },
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


def setup_document_version_mock_env(client):
    client.create_document(
        Content=json.dumps(MOCK_SSM_DOCUMENT),
        Name='MockSSMDocument',
    )
    new_content = dict()
    new_content.update(MOCK_SSM_DOCUMENT, description='An Updated Mock SSM Document' )
    response = client.update_document(
        Content=json.dumps(new_content),
        Name='MockSSMDocument',
    )
