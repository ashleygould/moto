from __future__ import unicode_literals

from collections import defaultdict

from moto.core import BaseBackend, BaseModel
from moto.core.utils import unix_time
from moto.ec2 import ec2_backends

import datetime
import time
import uuid
import json
import hashlib

FAKE_ACCOUNT_ID = '123456789012'


class Parameter(BaseModel):
    def __init__(self, name, value, type, description, keyid, last_modified_date, version):
        self.name = name
        self.type = type
        self.description = description
        self.keyid = keyid
        self.last_modified_date = last_modified_date
        self.version = version

        if self.type == 'SecureString':
            self.value = self.encrypt(value)
        else:
            self.value = value

    def encrypt(self, value):
        return 'kms:{}:'.format(self.keyid or 'default') + value

    def decrypt(self, value):
        if self.type != 'SecureString':
            return value

        prefix = 'kms:{}:'.format(self.keyid or 'default')
        if value.startswith(prefix):
            return value[len(prefix):]

    def response_object(self, decrypt=False):
        r = {
            'Name': self.name,
            'Type': self.type,
            'Value': self.decrypt(self.value) if decrypt else self.value,
            'Version': self.version,
        }

        return r

    def describe_response_object(self, decrypt=False):
        r = self.response_object(decrypt)
        r['LastModifiedDate'] = int(self.last_modified_date)
        r['LastModifiedUser'] = 'N/A'

        if self.description:
            r['Description'] = self.description

        if self.keyid:
            r['KeyId'] = self.keyid
        return r


class Document(BaseModel):
    """
    response = client.create_document(
        Content='string',
        Name='string',
        DocumentType='Command'|'Policy'|'Automation',
        DocumentFormat='YAML'|'JSON',
        TargetType='string'
    )
    """

    def __init__(self, content, name, **kwargs):
        self.content = json.loads(content)
        self.name = name
        self.sha256_digest = hashlib.sha256(content.encode()).hexdigest()
        self.created_time = datetime.datetime.utcnow()
        self.document_type=kwargs.get('DocumentType', 'Command')
        self.document_format=kwargs.get('DocumentFormat', 'JSON')
        self.target_type=kwargs.get('TargetType', '')
        self.owner=FAKE_ACCOUNT_ID
        self.document_history=[content]
        self.document_version=1
        self.latest_version=1
        self.default_version=1

    def _describe(self):
        return {
            'Hash': self.sha256_digest,
            'HashType': 'Sha256',
            'Name': self.name,
            'Owner': self.owner,
            'CreatedDate': unix_time(self.created_time),
            'Status': 'Active',
            'DocumentVersion': str(self.document_version),
            'Description': self.content['description'],
            'Parameters': [],
            'PlatformTypes': ['Linux'],
            'DocumentType': self.document_type,
            'SchemaVersion': self.content['schemaVersion'],
            'LatestVersion': str(self.latest_version),
            'DefaultVersion': str(self.default_version),
            'DocumentFormat': self.document_format,
            'TargetType': self.target_type,
            'Tags': [],
        }


class SimpleSystemManagerBackend(BaseBackend):

    def __init__(self):
        self._parameters = {}
        self._resource_tags = defaultdict(lambda: defaultdict(dict))
        self._documents = []

    def delete_parameter(self, name):
        try:
            del self._parameters[name]
        except KeyError:
            pass

    def delete_parameters(self, names):
        result = []
        for name in names:
            try:
                del self._parameters[name]
                result.append(name)
            except KeyError:
                pass
        return result

    def get_all_parameters(self):
        result = []
        for k, _ in self._parameters.items():
            result.append(self._parameters[k])
        return result

    def get_parameters(self, names, with_decryption):
        result = []
        for name in names:
            if name in self._parameters:
                result.append(self._parameters[name])
        return result

    def get_parameters_by_path(self, path, with_decryption, recursive, filters=None):
        """Implement the get-parameters-by-path-API in the backend."""
        result = []
        # path could be with or without a trailing /. we handle this
        # difference here.
        path = path.rstrip('/') + '/'
        for param in self._parameters:
            if path != '/' and not param.startswith(path):
                continue
            if '/' in param[len(path) + 1:] and not recursive:
                continue
            if not self._match_filters(self._parameters[param], filters):
                continue
            result.append(self._parameters[param])

        return result

    @staticmethod
    def _match_filters(parameter, filters=None):
        """Return True if the given parameter matches all the filters"""
        for filter_obj in (filters or []):
            key = filter_obj['Key']
            option = filter_obj.get('Option', 'Equals')
            values = filter_obj.get('Values', [])

            what = None
            if key == 'Type':
                what = parameter.type
            elif key == 'KeyId':
                what = parameter.keyid

            if option == 'Equals'\
                    and not any(what == value for value in values):
                return False
            elif option == 'BeginsWith'\
                    and not any(what.startswith(value) for value in values):
                return False
        # True if no false match (or no filters at all)
        return True

    def get_parameter(self, name, with_decryption):
        if name in self._parameters:
            return self._parameters[name]
        return None

    def put_parameter(self, name, description, value, type, keyid, overwrite):
        previous_parameter = self._parameters.get(name)
        version = 1

        if previous_parameter:
            version = previous_parameter.version + 1

            if not overwrite:
                return

        last_modified_date = time.time()
        self._parameters[name] = Parameter(
            name, value, type, description, keyid, last_modified_date, version)
        return version

    def add_tags_to_resource(self, resource_type, resource_id, tags):
        for key, value in tags.items():
            self._resource_tags[resource_type][resource_id][key] = value

    def remove_tags_from_resource(self, resource_type, resource_id, keys):
        tags = self._resource_tags[resource_type][resource_id]
        for key in keys:
            if key in tags:
                del tags[key]

    def list_tags_for_resource(self, resource_type, resource_id):
        return self._resource_tags[resource_type][resource_id]

    def send_command(self, **kwargs):
        instances = kwargs.get('InstanceIds', [])
        now = datetime.datetime.now()
        expires_after = now + datetime.timedelta(0, int(kwargs.get('TimeoutSeconds', 3600)))
        return {
            'Command': {
                'CommandId': str(uuid.uuid4()),
                'DocumentName': kwargs['DocumentName'],
                'Comment': kwargs.get('Comment'),
                'ExpiresAfter': expires_after.isoformat(),
                'Parameters': kwargs['Parameters'],
                'InstanceIds': kwargs['InstanceIds'],
                'Targets': kwargs.get('targets'),
                'RequestedDateTime': now.isoformat(),
                'Status': 'Success',
                'StatusDetails': 'string',
                'OutputS3Region': kwargs.get('OutputS3Region'),
                'OutputS3BucketName': kwargs.get('OutputS3BucketName'),
                'OutputS3KeyPrefix': kwargs.get('OutputS3KeyPrefix'),
                'MaxConcurrency': 'string',
                'MaxErrors': 'string',
                'TargetCount': len(instances),
                'CompletedCount': len(instances),
                'ErrorCount': 0,
                'ServiceRole': kwargs.get('ServiceRoleArn'),
                'NotificationConfig': {
                    'NotificationArn': 'string',
                    'NotificationEvents': ['Success'],
                    'NotificationType': 'Command'
                }
            }
        }

    def create_document(self, **kwargs):
        document = Document(kwargs['Content'], kwargs['Name'], **kwargs)
        self._documents.append(document)
        return {'DocumentDescription': document._describe()}

    def delete_document(self, **kwargs):
        try:
            document = [
                document for document in self._documents
                if document.name == kwargs['Name']
            ].pop(0)
        except IndexError as e:
            #raise boto error ???
            return dict()
        self._documents.remove(document)
        return {}

    def describe_document(self, **kwargs):
        try:
            document = [
                document for document in self._documents
                if document.name == kwargs['Name']
            ].pop(0)
        except IndexError as e:
            #raise boto error ???
            return dict()
        return {'Document': document._describe()}

    def list_documents(self, **kwargs):
        identifiers = []
        listing_keys = [
            'Name',
            'Owner',
            'PlatformTypes',
            'DocumentVersion',
            'DocumentType',
            'SchemaVersion',
            'DocumentFormat',
            'TargetType',
            'Tags',
        ]
        for document in self._documents:
            desc = document._describe()
            listing = {key: value for key,value in desc.items() if key in listing_keys}
            identifiers.append(listing)
        return {'DocumentIdentifiers': identifiers}


ssm_backends = {}
for region, ec2_backend in ec2_backends.items():
    ssm_backends[region] = SimpleSystemManagerBackend()
