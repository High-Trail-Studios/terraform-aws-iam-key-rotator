import json
import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from fakes import Clock, FakeDynamo, FakeIam, FakeSns, FakeSsm, sts_factory  # noqa: E402
from rotator import handler as handler_module  # noqa: E402
from rotator.aws import Iam, KeyNotVerified, Publisher, StateTable, verify_key  # noqa: E402
from rotator.config import Config  # noqa: E402
from rotator.handler import Rotator, publish  # noqa: E402
from rotator.policy import (  # noqa: E402
    AccessKey,
    Action,
    Level,
    Phase,
    Rotation,
    Thresholds,
    decide,
    parameter_name,
    review_exclusion,
)

TAG = "key-rotator"
ENV = {
    "ROTATOR_NAME": "iam-key-rotator",
    "ROTATOR_MODE": "enforce",
    "ROTATOR_TAG_KEY": TAG,
    "ROTATOR_USER_PATH_PREFIX": "/",
    "ROTATOR_CREATE_AFTER_DAYS": "65",
    "ROTATOR_DEACTIVATE_AFTER_DAYS": "75",
    "ROTATOR_DELETE_AFTER_DAYS": "85",
    "ROTATOR_MIN_DAYS_BEFORE_DEACTIVATE": "10",
    "ROTATOR_MIN_DAYS_BEFORE_DELETE": "10",
    "ROTATOR_IN_USE_WINDOW_DAYS": "7",
    "ROTATOR_MAX_ACTIONS_PER_RUN": "10",
    "ROTATOR_SSM_PREFIX": "/iam-key-rotator/",
    "ROTATOR_STATE_TABLE": "iam-key-rotator-state",
    "ROTATOR_ALERT_TOPIC_ARN": "arn:aws:sns:us-east-1:111111111111:alerts",
}
T = Thresholds()


def config(**overrides):
    return Config.from_env({**ENV, **{f"ROTATOR_{k.upper()}": str(v) for k, v in overrides.items()}})


# --- Pure policy --------------------------------------------------------------


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.now = Clock().now

    def key(self, age, status="Active", used_days_ago=None, key_id="AKIAOLD"):
        used = self.now - timedelta(days=used_days_ago) if used_days_ago is not None else None
        return AccessKey(key_id, status, self.now - timedelta(days=age), used)

    def rotation(self, phase, started_days_ago=10, deactivated_days_ago=None, new="AKIANEW"):
        return Rotation(
            phase=phase,
            old_key_id="AKIAOLD",
            started_at=self.now - timedelta(days=started_days_ago),
            parameter="/p/u",
            new_key_id=new,
            deactivated_at=self.now - timedelta(days=deactivated_days_ago) if deactivated_days_ago is not None else None,
        )

    def test_young_key_is_left_alone(self):
        self.assertEqual(decide([self.key(64)], None, T, self.now).action, Action.NONE)

    def test_creates_at_threshold(self):
        self.assertEqual(decide([self.key(65)], None, T, self.now).action, Action.CREATE)

    def test_two_keys_without_rotation_warns_and_holds(self):
        d = decide([self.key(30), self.key(10, key_id="AKIAX")], None, T, self.now)
        self.assertEqual((d.action, d.level), (Action.NONE, Level.WARN))

    def test_single_inactive_key_warns_and_is_never_deleted(self):
        d = decide([self.key(200, status="Inactive")], None, T, self.now)
        self.assertEqual((d.action, d.level), (Action.NONE, Level.WARN))

    def test_deactivates_when_old_enough_waited_and_idle(self):
        keys = [self.key(75, used_days_ago=8), self.key(10, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.CREATED, started_days_ago=10), T, self.now)
        self.assertEqual(d.action, Action.DEACTIVATE)

    def test_holds_deactivation_while_old_key_in_use(self):
        keys = [self.key(80, used_days_ago=1), self.key(15, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.CREATED, started_days_ago=15), T, self.now)
        self.assertEqual((d.action, d.level), (Action.NONE, Level.WARN))
        self.assertIn("/p/u", d.message)

    def test_minimum_wait_protects_overdue_keys(self):
        # A 120-day-old key on its first enforcing run: past every threshold,
        # but the replacement was only published 3 days ago.
        keys = [self.key(123), self.key(3, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.CREATED, started_days_ago=3), T, self.now)
        self.assertEqual(d.action, Action.NONE)

    def test_never_deletes_a_key_it_did_not_deactivate(self):
        keys = [self.key(90, status="Inactive"), self.key(25, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.CREATED, started_days_ago=25), T, self.now)
        self.assertEqual((d.action, d.level), (Action.NONE, Level.WARN))

    def test_deletes_after_both_waits(self):
        keys = [self.key(85, status="Inactive"), self.key(20, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.DEACTIVATED, 20, deactivated_days_ago=10), T, self.now)
        self.assertEqual(d.action, Action.DELETE)

    def test_delete_waits_after_deactivation(self):
        keys = [self.key(130, status="Inactive"), self.key(15, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.DEACTIVATED, 15, deactivated_days_ago=5), T, self.now)
        self.assertEqual(d.action, Action.NONE)

    def test_reenabled_old_key_is_a_rollback(self):
        keys = [self.key(90), self.key(25, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.DEACTIVATED, 25, deactivated_days_ago=12), T, self.now)
        self.assertEqual((d.action, d.level), (Action.REOPEN, Level.WARN))

    def test_unknown_third_party_key_holds(self):
        keys = [self.key(80), self.key(1, key_id="AKIASURPRISE")]
        d = decide(keys, self.rotation(Phase.CREATED, new="AKIANEW"), T, self.now)
        self.assertEqual((d.action, d.level), (Action.NONE, Level.WARN))

    def test_missing_replacement_forgets_without_touching_old(self):
        d = decide([self.key(80)], self.rotation(Phase.CREATED), T, self.now)
        self.assertEqual(d.action, Action.FORGET)

    def test_old_key_removed_by_hand_completes(self):
        d = decide([self.key(20, key_id="AKIANEW")], self.rotation(Phase.DEACTIVATED, 20, 10), T, self.now)
        self.assertEqual((d.action, d.level), (Action.FORGET, Level.INFO))

    def test_inactive_replacement_holds(self):
        keys = [self.key(80, used_days_ago=30), self.key(15, status="Inactive", key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.CREATED, 15), T, self.now)
        self.assertEqual((d.action, d.level), (Action.NONE, Level.WARN))

    def test_interrupted_creation_recreates_unpublished_key(self):
        keys = [self.key(70), self.key(0, key_id="AKIANEW")]
        d = decide(keys, self.rotation(Phase.CREATING, 0), T, self.now)
        self.assertEqual(d.action, Action.RECREATE)

    def test_exclusion_needs_reason_and_unexpired_date(self):
        keys = [self.key(200)]
        ok = review_exclusion({f"{TAG}:reason": "vendor", f"{TAG}:skip-until": "2026-06-01"}, TAG, keys, self.now)
        self.assertEqual(ok.level, Level.OK)
        self.assertIn("200d", ok.message)
        for tags in (
            {f"{TAG}:skip-until": "2026-06-01"},
            {f"{TAG}:reason": "vendor"},
            {f"{TAG}:reason": "vendor", f"{TAG}:skip-until": "2025-12-31"},
            {f"{TAG}:reason": "vendor", f"{TAG}:skip-until": "soon"},
        ):
            self.assertEqual(review_exclusion(tags, TAG, keys, self.now).level, Level.WARN, tags)

    def test_parameter_name_stays_under_prefix(self):
        self.assertEqual(parameter_name("/r", "ci-bot", None), "/r/ci-bot")
        self.assertEqual(parameter_name("/r", "ci-bot", "/team/ci/"), "/r/team/ci")
        self.assertIsNone(parameter_name("/r", "bob@example.com", None))
        self.assertIsNone(parameter_name("/r", "u", "../other"))
        self.assertIsNone(parameter_name("/r", "u", "a b"))


# --- Handler against fakes ----------------------------------------------------


class World:
    """A fake account the rotator runs against, one simulated day at a time."""

    def __init__(self, **cfg):
        self.clock = Clock()
        self.iam = FakeIam(self.clock)
        self.dynamo = FakeDynamo()
        self.ssm = FakeSsm()
        self.sts_broken = False
        self.config = config(**cfg)

    def rotator(self):
        return Rotator(
            self.config,
            Iam(self.iam),
            StateTable(self.dynamo, self.config.state_table),
            Publisher(self.ssm),
            sts_factory(self.iam, broken=self.sts_broken),
            clock=self.clock,
            sleep=lambda s: None,
        )

    def run(self):
        return self.rotator().run()

    def advance(self, days=1):
        self.clock.now += timedelta(days=days)


class HandlerTest(unittest.TestCase):
    def enrolled(self, world, name="ci-bot", age=0, **tags):
        world.iam.add_user(name, {TAG: "enabled", **tags})
        return world.iam.add_key(name, world.clock.now - timedelta(days=age))

    def test_full_lifecycle_stays_under_90_days(self):
        w = World()
        old = self.enrolled(w)
        log = {}
        for day in range(1, 101):
            w.advance()
            for o in w.run().outcomes:
                if o.status == "done":
                    log[o.decision.action] = day
        self.assertEqual(log, {Action.CREATE: 65, Action.DEACTIVATE: 75, Action.DELETE: 85})
        keys = w.iam.keys_of("ci-bot")
        self.assertEqual(len(keys), 1)
        self.assertNotIn(old, keys)
        value = json.loads(w.ssm.parameters["/iam-key-rotator/ci-bot"]["Value"])
        self.assertEqual(value["AccessKeyId"], next(iter(keys)))
        self.assertEqual(w.ssm.parameters["/iam-key-rotator/ci-bot"]["Type"], "SecureString")
        self.assertEqual(w.dynamo.items, {})

    def test_consumer_still_on_old_key_delays_deactivation(self):
        w = World()
        old = self.enrolled(w, age=60)
        deactivated_on = None
        for day in range(1, 40):
            w.advance()
            if day <= 12:  # the consumer keeps using the old key until day 12
                w.iam.keys_of("ci-bot")[old]["last_used"] = w.clock.now
            for o in w.run().outcomes:
                if o.status == "done" and o.decision.action == Action.DEACTIVATE:
                    deactivated_on = day
        # Old key turns 75 on day 15, but it was last used on day 12.
        self.assertEqual(deactivated_on, 19)

    def test_overdue_key_still_gets_full_rollback_windows(self):
        w = World()
        self.enrolled(w, age=120)
        log = {}
        for day in range(0, 30):
            for o in w.run().outcomes:
                if o.status == "done":
                    log[o.decision.action] = day
            w.advance()
        self.assertEqual(log, {Action.CREATE: 0, Action.DEACTIVATE: 10, Action.DELETE: 20})

    def test_report_mode_changes_nothing(self):
        w = World(mode="report")
        old = self.enrolled(w, age=100)
        report = w.run()
        self.assertEqual([o.status for o in report.outcomes], ["would"])
        self.assertEqual(list(w.iam.keys_of("ci-bot")), [old])
        self.assertEqual((w.dynamo.items, w.ssm.parameters), ({}, {}))
        self.assertIn("REPORT MODE", report.body())

    def test_untagged_users_are_never_touched(self):
        w = World()
        w.iam.add_user("human")
        old = w.iam.add_key("human", w.clock.now - timedelta(days=400))
        report = w.run()
        self.assertEqual((report.outcomes, report.ignored), ([], 1))
        self.assertEqual(list(w.iam.keys_of("human")), [old])

    def test_excluded_user_is_reported_not_rotated(self):
        w = World()
        self.enrolled(w, name="vendor", age=300)
        w.iam.users["vendor"]["tags"][TAG] = "skip"
        report = w.run()
        self.assertEqual(report.outcomes[0].status, "excluded")
        self.assertEqual(len(report.warnings), 1)  # no reason, no expiry
        self.assertEqual(len(w.iam.keys_of("vendor")), 1)

    def test_unknown_tag_value_warns(self):
        w = World()
        self.enrolled(w, age=100)
        w.iam.users["ci-bot"]["tags"][TAG] = "yes"
        report = w.run()
        self.assertEqual(len(report.warnings), 1)
        self.assertEqual(len(w.iam.keys_of("ci-bot")), 1)

    def test_failed_verification_discards_new_key(self):
        w = World()
        old = self.enrolled(w, age=70)
        w.sts_broken = True
        report = w.run()
        self.assertEqual(len(report.errors), 1)
        self.assertIn("old key untouched", report.errors[0].decision.message)
        self.assertEqual(list(w.iam.keys_of("ci-bot")), [old])
        self.assertEqual((w.dynamo.items, w.ssm.parameters), ({}, {}))

    def test_failed_publish_discards_new_key(self):
        w = World()
        old = self.enrolled(w, age=70)
        w.ssm.fail = True
        self.assertEqual(len(w.run().errors), 1)
        self.assertEqual(list(w.iam.keys_of("ci-bot")), [old])

    def test_interrupted_run_is_recovered(self):
        w = World()
        old = self.enrolled(w, age=70)
        # Simulate a run that died after creating the key, before publishing.
        orphan = w.iam.add_key("ci-bot", w.clock.now)
        StateTable(w.dynamo, "t").put(
            "ci-bot", Rotation(Phase.CREATING, old, w.clock.now, "/iam-key-rotator/ci-bot", orphan)
        )
        w.run()
        keys = w.iam.keys_of("ci-bot")
        self.assertNotIn(orphan, keys)
        self.assertIn(old, keys)
        self.assertEqual(len(keys), 2)
        self.assertEqual(w.dynamo.items["ci-bot"]["phase"]["S"], "created")

    def test_rollback_by_reenabling_prevents_delete(self):
        w = World()
        old = self.enrolled(w, age=74)
        for _ in range(12):  # create on day 0, deactivate on day 10
            w.run()
            w.advance()
        self.assertEqual(w.iam.keys_of("ci-bot")[old]["status"], "Inactive")
        w.iam.keys_of("ci-bot")[old]["status"] = "Active"  # a human rolls back
        for _ in range(3):
            w.iam.keys_of("ci-bot")[old]["last_used"] = w.clock.now
            w.run()
            w.advance()
        self.assertEqual(w.iam.keys_of("ci-bot")[old]["status"], "Active")
        self.assertEqual(w.dynamo.items["ci-bot"]["phase"]["S"], "created")

    def test_max_actions_per_run_defers_the_rest(self):
        w = World(max_actions_per_run=2)
        for i in range(3):
            self.enrolled(w, name=f"bot{i}", age=70)
        report = w.run()
        self.assertEqual(sorted(o.status for o in report.outcomes), ["deferred", "done", "done"])

    def test_concurrent_start_is_refused(self):
        w = World()
        self.enrolled(w, age=70)
        table = StateTable(w.dynamo, "t")
        r = Rotation(Phase.CREATING, "x", w.clock.now, "/p")
        table.put("other", r, new=True)
        with self.assertRaises(Exception):
            table.put("other", r, new=True)

    def test_secret_never_reaches_logs_or_digest(self):
        w = World()
        self.enrolled(w, age=70)
        with self.assertLogs("rotator", level="INFO") as logs:
            report = w.run()
        secret = json.loads(w.ssm.parameters["/iam-key-rotator/ci-bot"]["Value"])["SecretAccessKey"]
        self.assertNotIn(secret, "\n".join(logs.output) + report.body())

    def test_user_name_invalid_for_ssm_needs_path_tag(self):
        w = World()
        self.enrolled(w, name="bob@example.com", age=70)
        report = w.run()
        self.assertEqual(len(report.warnings), 1)
        self.assertEqual(len(w.iam.keys_of("bob@example.com")), 1)
        w.iam.users["bob@example.com"]["tags"][f"{TAG}:ssm-path"] = "people/bob"
        w.run()
        self.assertIn("/iam-key-rotator/people/bob", w.ssm.parameters)


class DigestTest(unittest.TestCase):
    def test_quiet_run_sends_nothing(self):
        w = World()
        w.iam.add_user("ci-bot", {TAG: "enabled"})
        w.iam.add_key("ci-bot", w.clock.now)
        sns = FakeSns()
        publish(w.run(), sns)
        self.assertEqual(sns.published, [])

    def test_notable_run_sends_one_digest(self):
        w = World()
        w.iam.add_user("ci-bot", {TAG: "enabled"})
        w.iam.add_key("ci-bot", w.clock.now - timedelta(days=70))
        sns = FakeSns()
        publish(w.run(), sns)
        self.assertEqual(len(sns.published), 1)
        topic, subject, message = sns.published[0]
        self.assertEqual(subject, "[iam-key-rotator] enforce: 1 action(s), 0 warning(s), 0 error(s)")
        self.assertIn("ci-bot", message)


class VerifyTest(unittest.TestCase):
    def test_retries_through_propagation_delay(self):
        attempts = []

        def factory(key_id, secret):
            class Sts:
                def get_caller_identity(self):
                    attempts.append(1)
                    if len(attempts) < 3:
                        raise RuntimeError("InvalidClientTokenId")
                    return {"Arn": "arn:aws:iam::111111111111:user/ci/ci-bot"}

            return Sts()

        verify_key("ci-bot", "AKIA", "s", factory, sleep=lambda s: None)
        self.assertEqual(len(attempts), 3)

    def test_wrong_identity_is_rejected(self):
        def factory(key_id, secret):
            class Sts:
                def get_caller_identity(self):
                    return {"Arn": "arn:aws:iam::111111111111:user/other"}

            return Sts()

        with self.assertRaises(KeyNotVerified):
            verify_key("ci-bot", "AKIA", "s", factory, sleep=lambda s: None)


class ConfigTest(unittest.TestCase):
    def test_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            config(mode="yolo")

    def test_strips_trailing_slash(self):
        self.assertEqual(config().ssm_prefix, "/iam-key-rotator")


if __name__ == "__main__":
    unittest.main()
