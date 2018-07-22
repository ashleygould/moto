from __future__ import unicode_literals

from collections import defaultdict

from moto.core import BaseBackend, BaseModel
from moto.core.exceptions import RESTError
from moto.core.utils import unix_time
from moto.ec2 import ec2_backends

import datetime
import time
import uuid
import json
import yaml
import hashlib
import re


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


MAX_TIMEOUT_SECONDS = 3600


class Command(BaseModel):
    def __init__(self, comment='', document_name='', timeout_seconds=MAX_TIMEOUT_SECONDS,
            instance_ids=None, max_concurrency='', max_errors='',
            notification_config=None, output_s3_bucket_name='',
            output_s3_key_prefix='', output_s3_region='', parameters=None,
            service_role_arn='', targets=None):

        if instance_ids is None:
            instance_ids = []

        if notification_config is None:
            notification_config = {}

        if parameters is None:
            parameters = {}

        if targets is None:
            targets = []

        self.error_count = 0
        self.completed_count = len(instance_ids)
        self.target_count = len(instance_ids)
        self.command_id = str(uuid.uuid4())
        self.status = 'Success'
        self.status_details = 'Details placeholder'

        now = datetime.datetime.now()
        self.requested_date_time = now.isoformat()
        expires_after = now + datetime.timedelta(0, timeout_seconds)
        self.expires_after = expires_after.isoformat()

        self.comment = comment
        self.document_name = document_name
        self.instance_ids = instance_ids
        self.max_concurrency = max_concurrency
        self.max_errors = max_errors
        self.notification_config = notification_config
        self.output_s3_bucket_name = output_s3_bucket_name
        self.output_s3_key_prefix = output_s3_key_prefix
        self.output_s3_region = output_s3_region
        self.parameters = parameters
        self.service_role_arn = service_role_arn
        self.targets = targets

    def response_object(self):
        r = {
            'CommandId': self.command_id,
            'Comment': self.comment,
            'CompletedCount': self.completed_count,
            'DocumentName': self.document_name,
            'ErrorCount': self.error_count,
            'ExpiresAfter': self.expires_after,
            'InstanceIds': self.instance_ids,
            'MaxConcurrency': self.max_concurrency,
            'MaxErrors': self.max_errors,
            'NotificationConfig': self.notification_config,
            'OutputS3Region': self.output_s3_region,
            'OutputS3BucketName': self.output_s3_bucket_name,
            'OutputS3KeyPrefix': self.output_s3_key_prefix,
            'Parameters': self.parameters,
            'RequestedDateTime': self.requested_date_time,
            'ServiceRole': self.service_role_arn,
            'Status': self.status,
            'StatusDetails': self.status_details,
            'TargetCount': self.target_count,
            'Targets': self.targets,
        }

        return r


class DocumentVersion(BaseModel):
    def __init__(self, content, document_format):
        self.sha256_digest = hashlib.sha256(content.encode()).hexdigest()
        self.created_time = datetime.datetime.utcnow()
        self.document_format = document_format

        if document_format == 'JSON':
            self.content = json.loads(content)
        elif document_format == 'YAML':
            self.content = yaml.load(content)
        else:
            raise RESTError(
                'ValidationException',
                "Value '{}' at 'documentFormat' failed to satisfy constraint: "
                "Member must satisfy enum value set: "
                "[YAML, JSON]".format(document_format),
            )


FAKE_ACCOUNT_ID = '123456789012'


class Document(BaseModel):

    def __init__(self, name, document_type, target_type):
        self.name = name
        self.owner = FAKE_ACCOUNT_ID
        self.default_version = ''
        self.document_versions = []

        if document_type not in ['Command', 'Policy', 'Automation']:
            raise RESTError(
                'ValidationException',
                "Value '{}' at 'documentType' failed to satisfy constraint: "
                "Member must satisfy enum value set: "
                "[Command, Policy, Automation]".format(document_type),
            )
        self.document_type = document_type

        if target_type is not None:
            target_type_re = re.compile(r'\/[\w\.\-\:\/]*')
            if not target_type_re.match(target_type):
                raise RESTError(
                    'ValidationException',
                    "Value '{}' at 'targetType' failed to satisfy constraint: "
                    "Member must satisfy regular expression pattern: "
                    "^\/[\w\.\-\:\/]*$".format(target_type),
                )
            self.target_type = target_type

    @property
    def latest_version(self):
        return str(len(self.document_versions))

    def index_from_version_str(self, version_str):
        try:
            return int(version_str) - 1
        except ValueError:
            raise RESTError(
                'ValidationException',
                "Value '{}' at 'documentVersion' failed to satisfy constraint: "
                "Member must satisfy regular expression pattern: "
                "([$]LATEST|[$]DEFAULT|^[1-9][0-9]*$".format(version_str)
            )

    def get_version(self, version_str):
        index = self.index_from_version_str(version_str)
        try:
            return self.document_versions[index]
        except IndexError:
            raise RESTError(
                'InvalidDocumentVersion',
                'Document version: {} is invalid for {}, latest version is {}'.format(
                    version_str,
                    self.name,
                    self.lastest_version
                ))

    def describe(self, version_str=None):
        if not version_str:
            version_str = self.default_version
        document_version = self.get_version(version_str)
        document_desc = {
            'Hash': document_version.sha256_digest,
            'HashType': 'Sha256',
            'Name': self.name,
            'Owner': self.owner,
            'CreatedDate': unix_time(document_version.created_time),
            'Status': 'Active',
            'DocumentVersion': version_str,
            'Description': document_version.content['description'],
            'Parameters': [],
            'PlatformTypes': ['Linux'],
            'DocumentType': self.document_type,
            'SchemaVersion': document_version.content['schemaVersion'],
            'LatestVersion': self.latest_version,
            'DefaultVersion': self.default_version,
            'DocumentFormat': document_version.document_format,
            'Tags': [],
        }
        if hasattr(self, 'target_type'):
            document_desc['TargetType'] = self.target_type
        return document_desc


class SimpleSystemManagerBackend(BaseBackend):

    def __init__(self):
        self._parameters = {}
        self._resource_tags = defaultdict(lambda: defaultdict(dict))
        self._commands = []
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
        command = Command(
            comment=kwargs.get('Comment', ''),
            document_name=kwargs.get('DocumentName'),
            timeout_seconds=kwargs.get('TimeoutSeconds', 3600),
            instance_ids=kwargs.get('InstanceIds', []),
            max_concurrency=kwargs.get('MaxConcurrency', '50'),
            max_errors=kwargs.get('MaxErrors', '0'),
            notification_config=kwargs.get('NotificationConfig', {
                'NotificationArn': 'string',
                'NotificationEvents': ['Success'],
                'NotificationType': 'Command'
            }),
            output_s3_bucket_name=kwargs.get('OutputS3BucketName', ''),
            output_s3_key_prefix=kwargs.get('OutputS3KeyPrefix', ''),
            output_s3_region=kwargs.get('OutputS3Region', ''),
            parameters=kwargs.get('Parameters', {}),
            service_role_arn=kwargs.get('ServiceRoleArn', ''),
            targets=kwargs.get('Targets', []))

        self._commands.append(command)
        return {
            'Command': command.response_object()
        }

    def list_commands(self, **kwargs):
        """
        https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ListCommands.html
        """
        commands = self._commands

        command_id = kwargs.get('CommandId', None)
        if command_id:
            commands = [self.get_command_by_id(command_id)]
        instance_id = kwargs.get('InstanceId', None)
        if instance_id:
            commands = self.get_commands_by_instance_id(instance_id)

        return {
            'Commands': [command.response_object() for command in commands]
        }

    def get_command_by_id(self, id):
        command = next(
            (command for command in self._commands if command.command_id == id), None)

        if command is None:
            raise RESTError('InvalidCommandId', 'Invalid command id.')

        return command

    def get_commands_by_instance_id(self, instance_id):
        return [
            command for command in self._commands
            if instance_id in command.instance_ids]

    def create_document(self, **kwargs):
        document = Document(
            kwargs['Name'],
            kwargs.get('DocumentType', 'Command'),
            kwargs.get('TargetType'),
        )
        document_version = DocumentVersion(
            kwargs['Content'],
            kwargs.get('DocumentFormat', 'JSON'),
        )
        document.default_version = '1'
        document.document_versions.append(document_version)
        self._documents.append(document)
        return {'DocumentDescription': document.describe()}

    def get_document_by_name(self, name):
        document = next((doc for doc in self._documents if doc.name == name), None)
        if document is None:
            raise RESTError(
                'InvalidDocument',
                'Document with name {} does not exist.'.format(name)
            )
        return document

    def describe_document(self, **kwargs):
        document = self.get_document_by_name(kwargs['Name'])
        return {'Document': document.describe(kwargs.get('DocumentVersion'))}

    def delete_document(self, **kwargs):
        document = self.get_document_by_name(kwargs['Name'])
        self._documents.remove(document)
        return {}

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
            desc = document.describe()
            listing = {key: value for key, value in desc.items() if key in listing_keys}
            identifiers.append(listing)
        return {'DocumentIdentifiers': identifiers}

    def update_document(self, **kwargs):
        document = self.get_document_by_name(kwargs['Name'])
        document_version = DocumentVersion(
            kwargs['Content'],
            kwargs.get('DocumentFormat', 'JSON'),
        )
        if 'DocumentVersion' in kwargs:
            version_index = document.index_from_version_str(kwargs['DocumentVersion'])
            document.document_versions[version_index] = document_version
        else:
            document.document_versions.append(document_version)
        version_str = str(document.document_versions.index(document_version) + 1)
        print(version_str)
        return {'DocumentDescription': document.describe(version_str)}

    def list_document_versions(self, **kwargs):
        document = self.get_document_by_name(kwargs['Name'])
        version_descriptions = []
        for document_version in document.document_versions:
            version_str = str(document.document_versions.index(document_version) + 1)
            version_descriptions.append(
                {
                    'Name': document.name,
                    'DocumentVersion': version_str,
                    'CreatedDate': unix_time(document_version.created_time),
                    'IsDefaultVersion': (version_str == document.default_version),
                    'DocumentFormat': document_version.document_format,
                }
            )
        return {'DocumentVersions': version_descriptions}

    def update_document_default_version(self, **kwargs):
        document = self.get_document_by_name(kwargs['Name'])
        index = self._documents.index(document)
        self._documents[index].default_version = kwargs['DocumentVersion']
        return {
            'Description': {
                'Name': self._documents[index].name,
                'DefaultVersion': self._documents[index].default_version,
            }
        }

    def get_document(self, **kwargs):
        document = self.get_document_by_name(kwargs['Name'])
        document_version = document.get_version(kwargs.get('DocumentVersion'))
        version_str = str(document.document_versions.index(document_version) + 1)
        return {
            'Name': document.name,
            'DocumentVersion': version_str,
            'Content': document_version.content,
            'DocumentType': document.document_type,
            'DocumentFormat': document_version.document_format,
        }


ssm_backends = {}
for region, ec2_backend in ec2_backends.items():
    ssm_backends[region] = SimpleSystemManagerBackend()
