import unittest

from dns_record_validator import (
    RecordError, Record, A, AAAA, MX, TXT, SRV, CNAME, SOA, validate,
)


class TestA(unittest.TestCase):
    def test_valid(self):
        rec = validate("A", name="www", address="192.0.2.1")
        self.assertIsInstance(rec, A)
        self.assertEqual(rec.as_dict(),
            {"type": "A", "name": "www", "address": "192.0.2.1"})

    def test_root_owner(self):
        rec = A(name=".", address="10.0.0.1")
        self.assertEqual(rec.name, ".")

    def test_trailing_dot_owner(self):
        rec = A(name="www.example.", address="10.0.0.1")
        self.assertEqual(rec.name, "www.example.")

    def test_leading_digit_owner(self):
        rec = A(name="3com.example", address="10.0.0.1")
        self.assertEqual(rec.name, "3com.example")

    def test_bad_address(self):
        with self.assertRaises(RecordError):
            A(name="www", address="999.0.0.1")

    def test_ipv6_address_rejected(self):
        with self.assertRaises(RecordError):
            A(name="www", address="::1")

    def test_all_numeric_owner_rejected(self):
        with self.assertRaises(RecordError):
            A(name="192.0.2.1", address="1.2.3.4")

    def test_long_label_rejected(self):
        with self.assertRaises(RecordError):
            A(name="a" * 64, address="1.2.3.4")

    def test_empty_name(self):
        with self.assertRaises(RecordError):
            A(name="", address="1.2.3.4")

    def test_missing_field(self):
        with self.assertRaises(RecordError):
            A(name="www")

    def test_extra_field(self):
        with self.assertRaises(RecordError):
            A(name="www", address="1.2.3.4", ttl=300)


class TestAAAA(unittest.TestCase):
    def test_valid(self):
        rec = validate("AAAA", name="www", address="2001:db8::1")
        self.assertIsInstance(rec, AAAA)
        self.assertEqual(rec.address, "2001:db8::1")

    def test_ipv4_rejected(self):
        with self.assertRaises(RecordError):
            AAAA(name="www", address="192.0.2.1")


class TestMX(unittest.TestCase):
    def test_valid(self):
        rec = validate("MX", name="example", preference=10, exchange="mail.example")
        self.assertIsInstance(rec, MX)
        self.assertEqual(rec.preference, 10)

    def test_root_exchange(self):
        rec = MX(name="example", preference=10, exchange=".")
        self.assertEqual(rec.exchange, ".")

    def test_preference_zero(self):
        rec = MX(name="example", preference=0, exchange="mail.example")
        self.assertEqual(rec.preference, 0)

    def test_preference_too_high(self):
        with self.assertRaises(RecordError):
            MX(name="example", preference=65536, exchange="mail.example")

    def test_preference_bool_rejected(self):
        with self.assertRaises(RecordError):
            MX(name="example", preference=True, exchange="mail.example")

    def test_preference_string_rejected(self):
        with self.assertRaises(RecordError):
            MX(name="example", preference="10", exchange="mail.example")

    def test_bad_exchange(self):
        with self.assertRaises(RecordError):
            MX(name="example", preference=10, exchange="-bad.example")


class TestTXT(unittest.TestCase):
    def test_valid(self):
        rec = validate("TXT", name="example", data="v=spf1 -all")
        self.assertIsInstance(rec, TXT)
        self.assertEqual(rec.data, "v=spf1 -all")

    def test_empty_data(self):
        rec = TXT(name="example", data="")
        self.assertEqual(rec.data, "")

    def test_long_data_rejected(self):
        with self.assertRaises(RecordError):
            TXT(name="example", data="x" * 65536)

    def test_non_string_rejected(self):
        with self.assertRaises(RecordError):
            TXT(name="example", data=b"bytes")


class TestSRV(unittest.TestCase):
    def test_valid(self):
        rec = validate("SRV", name="_sip._tcp.example",
            priority=10, weight=20, port=5060, target="sip.example")
        self.assertIsInstance(rec, SRV)
        self.assertEqual(rec.port, 5060)

    def test_trailing_dot(self):
        rec = SRV(name="_sip._tcp.example.", priority=10,
                  weight=20, port=5060, target="sip.example.")
        self.assertEqual(rec.name, "_sip._tcp.example.")

    def test_unknown_proto_rejected(self):
        with self.assertRaises(RecordError):
            SRV(name="_sip._foo.example", priority=10,
                 weight=20, port=5060, target="sip.example")

    def test_missing_service_prefix(self):
        with self.assertRaises(RecordError):
            SRV(name="sip.tcp.example", priority=10,
                 weight=20, port=5060, target="sip.example")

    def test_port_out_of_range(self):
        with self.assertRaises(RecordError):
            SRV(name="_sip._tcp.example", priority=10,
                 weight=20, port=70000, target="sip.example")

    def test_weight_bool_rejected(self):
        with self.assertRaises(RecordError):
            SRV(name="_sip._tcp.example", priority=10,
                 weight=False, port=5060, target="sip.example")


class TestCNAME(unittest.TestCase):
    def test_valid(self):
        rec = validate("CNAME", name="alias.example", target="real.example")
        self.assertIsInstance(rec, CNAME)
        self.assertEqual(rec.target, "real.example")

    def test_root_target(self):
        rec = CNAME(name="alias.example", target=".")
        self.assertEqual(rec.target, ".")

    def test_bad_target(self):
        with self.assertRaises(RecordError):
            CNAME(name="alias.example", target="bad!.example")


class TestSOA(unittest.TestCase):
    def test_valid(self):
        rec = validate("SOA", name="example", mname="ns.example",
            rname="hostmaster.example", serial=1, refresh=3600,
            retry=900, expire=604800, minimum=86400)
        self.assertIsInstance(rec, SOA)
        self.assertEqual(rec.serial, 1)

    def test_max_values(self):
        rec = SOA(name="example", mname="ns.example",
            rname="hostmaster.example", serial=0xFFFFFFFF,
            refresh=0xFFFFFFFF, retry=0xFFFFFFFF,
            expire=0xFFFFFFFF, minimum=0xFFFFFFFF)
        self.assertEqual(rec.serial, 0xFFFFFFFF)

    def test_serial_too_high(self):
        with self.assertRaises(RecordError):
            SOA(name="example", mname="ns.example",
                rname="hostmaster.example", serial=0x100000000,
                refresh=1, retry=1, expire=1, minimum=1)

    def test_serial_bool_rejected(self):
        with self.assertRaises(RecordError):
            SOA(name="example", mname="ns.example",
                rname="hostmaster.example", serial=True,
                refresh=1, retry=1, expire=1, minimum=1)

    def test_bad_rname(self):
        with self.assertRaises(RecordError):
            SOA(name="example", mname="ns.example",
                rname="hostmaster", serial=1,
                refresh=1, retry=1, expire=1, minimum=1)

    def test_bad_mname(self):
        with self.assertRaises(RecordError):
            SOA(name="example", mname="-bad",
                rname="hostmaster.example", serial=1,
                refresh=1, retry=1, expire=1, minimum=1)


class TestDispatch(unittest.TestCase):
    def test_unknown_type(self):
        with self.assertRaises(RecordError):
            validate("NSEC", name="example")

    def test_equality(self):
        self.assertEqual(A(name="w", address="1.2.3.4"),
                         A(name="w", address="1.2.3.4"))
        self.assertNotEqual(A(name="w", address="1.2.3.4"),
                            A(name="w", address="1.2.3.5"))

    def test_repr(self):
        self.assertEqual(repr(A(name="w", address="1.2.3.4")),
            "A(name='w', address='1.2.3.4')")


if __name__ == "__main__":
    unittest.main()
