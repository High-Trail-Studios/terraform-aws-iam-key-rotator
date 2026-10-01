"""In-memory stand-ins for the boto3 clients the rotator uses.

They model the behaviour the design depends on: the two-key limit, secrets
returned only at creation, last-used dates, and conditional puts.
"""

import itertools
from datetime import UTC, datetime


class ClientError(Exception):
    pass


class FakeIam:
    def __init__(self, clock):
        self.clock = clock
        self.users = {}  # name -> {"path", "tags", "keys": {id: {...}}}
        self.secrets = {}  # key id -> secret, for the fake STS
        self._ids = itertools.count(1)

    def add_user(self, name, tags=None, path="/"):
        self.users[name] = {"path": path, "tags": dict(tags or {}), "keys": {}}

    def add_key(self, user, created, status="Active", last_used=None):
        key_id = f"AKIA{next(self._ids):012d}"
        self.users[user]["keys"][key_id] = {"status": status, "created": created, "last_used": last_used}
        self.secrets[key_id] = f"secret-{key_id}"
        return key_id

    def keys_of(self, user):
        return self.users[user]["keys"]

    # --- boto3 surface ---

    def get_paginator(self, op):
        fake = self

        class Paginator:
            def paginate(self, **kw):
                if op == "list_users":
                    names = [n for n, u in fake.users.items() if u["path"].startswith(kw["PathPrefix"])]
                    yield {"Users": [{"UserName": n} for n in names[:1]]}
                    yield {"Users": [{"UserName": n} for n in names[1:]]}
                elif op == "list_user_tags":
                    tags = fake.users[kw["UserName"]]["tags"]
                    yield {"Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}

        return Paginator()

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [
            {"AccessKeyId": k, "Status": v["status"], "CreateDate": v["created"]}
            for k, v in self.keys_of(UserName).items()
        ]}

    def get_access_key_last_used(self, AccessKeyId):
        for u in self.users.values():
            if AccessKeyId in u["keys"]:
                used = u["keys"][AccessKeyId]["last_used"]
                return {"AccessKeyLastUsed": {"LastUsedDate": used} if used else {}}
        raise ClientError("NoSuchEntity")

    def create_access_key(self, UserName):
        if len(self.keys_of(UserName)) >= 2:
            raise ClientError("LimitExceeded")
        key_id = self.add_key(UserName, self.clock())
        return {"AccessKey": {"AccessKeyId": key_id, "SecretAccessKey": self.secrets[key_id]}}

    def update_access_key(self, UserName, AccessKeyId, Status):
        self.keys_of(UserName)[AccessKeyId]["status"] = Status

    def delete_access_key(self, UserName, AccessKeyId):
        del self.keys_of(UserName)[AccessKeyId]
        del self.secrets[AccessKeyId]


class FakeDynamo:
    def __init__(self):
        self.items = {}

    def get_item(self, TableName, Key, ConsistentRead):
        item = self.items.get(Key["user_name"]["S"])
        return {"Item": item} if item else {}

    def put_item(self, TableName, Item, ConditionExpression=None):
        user = Item["user_name"]["S"]
        if ConditionExpression and user in self.items:
            raise ClientError("ConditionalCheckFailedException")
        self.items[user] = Item

    def delete_item(self, TableName, Key):
        self.items.pop(Key["user_name"]["S"], None)


class FakeSsm:
    def __init__(self):
        self.parameters = {}
        self.fail = False

    def put_parameter(self, **kw):
        if self.fail:
            raise ClientError("AccessDenied")
        self.parameters[kw["Name"]] = kw


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, TopicArn, Subject, Message):
        self.published.append((TopicArn, Subject, Message))


def sts_factory(iam, broken=False):
    def make(key_id, secret):
        class Sts:
            def get_caller_identity(self):
                if broken:
                    raise ClientError("InvalidClientTokenId")
                for name, u in iam.users.items():
                    if key_id in u["keys"] and iam.secrets.get(key_id) == secret:
                        return {"Arn": f"arn:aws:iam::111111111111:user{u['path']}{name}"}
                raise ClientError("InvalidClientTokenId")

        return Sts()

    return make


class Clock:
    def __init__(self, start=datetime(2026, 1, 1, 6, 0, tzinfo=UTC)):
        self.now = start

    def __call__(self):
        return self.now
