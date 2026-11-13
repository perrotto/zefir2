"""Testy bez połączenia z PUESC: udawany serwer SOAP zamiast requests.Session.

Uruchomienie:  python -m unittest discover -s tests -v
"""
import base64
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from lxml import etree

KATALOG = Path(__file__).resolve().parent
sys.path.insert(0, str(KATALOG.parent))
os.environ["ZEFIR_DATA"] = tempfile.mkdtemp(prefix="zefir2-test-")

import pzas  # noqa: E402
import seap  # noqa: E402

PRZYKLAD = (KATALOG / "dane" / "PZASResp_przyklad.xml").read_bytes()
VIN = "AUDIA42021053001"  # VIN z przykładowej odpowiedzi ze specyfikacji ZEFIR2


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def odpowiedz_soap(cialo: str) -> bytes:
    return (f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>{cialo}'
            f'</soap:Body></soap:Envelope>').encode()


class UdawanyPuesc:
    """Zachowuje się jak requests.Session dla DocumentHandlingPort."""
    wyslane: list = []
    dokumenty: list = []

    def __init__(self):
        pass

    def post(self, url, data, timeout, headers):
        UdawanyPuesc.wyslane.append(data)
        root = etree.fromstring(data)
        op = etree.QName(root.find(".//{%s}Body" % seap.NS_SOAP)[0]).localname
        if op == "AcceptDocumentRequest":
            tekst = (b'<ns2:AcceptDocumentResponse xmlns:ns2="urn:x" xmlns="urn:t"><result>'
                     b'<sysRef>SYS-123</sysRef></result></ns2:AcceptDocumentResponse>')
            return Odp(200, odpowiedz_soap(tekst.decode()))
        if op == "GetDocumentsRequest":
            dok = "".join(f'<document><content filename="{n}" mime="application/xml">{b64(x)}</content></document>'
                          for n, x in UdawanyPuesc.dokumenty)
            return Odp(200, odpowiedz_soap(f'<GetDocumentsResponse xmlns="urn:t">{dok}</GetDocumentsResponse>'))
        return Odp(500, odpowiedz_soap("<soap:Fault><faultcode>x</faultcode>"
                                       "<faultstring>nieznana operacja</faultstring></soap:Fault>"))

    def get(self, url, timeout):
        return Odp(200, WSDL)


class Odp:
    def __init__(self, status, content):
        self.status_code, self.content = status, content
        self.text = content.decode("utf-8", "replace")

    def raise_for_status(self):
        pass


WSDL = b"""<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:wsam="http://www.w3.org/2007/05/addressing/metadata" xmlns:tns="urn:usluga" xmlns:t="urn:typy"
  targetNamespace="urn:usluga">
  <wsdl:types><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:typy" elementFormDefault="qualified">
    <xs:complexType name="documentType"/><xs:element name="AcceptDocumentRequest"/></xs:schema></wsdl:types>
  <wsdl:message name="AcceptDocumentRequest"><wsdl:part name="p" element="t:AcceptDocumentRequest"/></wsdl:message>
  <wsdl:message name="GetDocumentsRequest"><wsdl:part name="p" element="t:GetDocumentsRequest"/></wsdl:message>
  <wsdl:portType name="DocumentHandling">
    <wsdl:operation name="AcceptDocument"><wsdl:input message="tns:AcceptDocumentRequest" wsam:Action="urn:usluga/AcceptDocument"/></wsdl:operation>
    <wsdl:operation name="GetDocuments"><wsdl:input message="tns:GetDocumentsRequest"/></wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="b" type="tns:DocumentHandling">
    <wsdl:operation name="GetDocuments"><soap:operation soapAction="urn:usluga/GetDocuments"/></wsdl:operation>
  </wsdl:binding>
</wsdl:definitions>"""


class TestSeap(unittest.TestCase):
    def test_digest_wg_specyfikacji(self):
        nonce, created = b"1234567890abcdef", "2021-09-24T14:41:50Z"
        skrot = base64.b64encode(hashlib.sha1(b"Haslo!").digest()).decode()
        oczekiwany = base64.b64encode(hashlib.sha1(nonce + created.encode() + skrot.encode()).digest()).decode()
        self.assertEqual(seap.skrot_hasla("Haslo!"), skrot)
        self.assertEqual(seap.password_digest(nonce, created, skrot), oczekiwany)

    def test_koperta_get_documents(self):
        k = seap.Klient(seap.domyslna_konfiguracja("test"), "a@b.pl", "x")
        env = etree.fromstring(k.koperta("GetDocuments", [(p, {"pobrany": 0, "dataDo": "2026-11-13",
                                                                "korelacjaSysref": "S"}.get(p))
                                                          for p in seap.POLA_GET_DOCUMENTS]))
        wrap = env.find(".//{%s}Body" % seap.NS_SOAP)[0]
        self.assertEqual(wrap.tag, f"{{{seap.NS_USLUGA}}}GetDocumentsRequest")
        self.assertEqual([etree.QName(e).localname for e in wrap], ["korelacjaSysref", "dataDo", "pobrany"])
        self.assertEqual(env.findtext(".//{%s}Username" % seap.NS_WSSE), "a@b.pl")
        self.assertRegex(env.findtext(".//{%s}Created" % seap.NS_WSU), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(env.findtext(".//{%s}MessageID" % seap.NS_WSA).startswith("urn:uuid:"))

    def test_wykrywanie_z_wsdl(self):
        konf = seap.wykryj_z_wsdl("https://x/DocumentHandlingPort", sesja=UdawanyPuesc())
        self.assertEqual(konf["operacje"]["AcceptDocument"]["element"], "{urn:typy}AcceptDocumentRequest")
        self.assertEqual(konf["operacje"]["AcceptDocument"]["akcja"], "urn:usluga/AcceptDocument")
        self.assertEqual(konf["operacje"]["GetDocuments"]["soap_action"], "urn:usluga/GetDocuments")
        self.assertEqual(konf["ns_typy"], "urn:typy")


class TestAplikacja(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seap.requests.Session = UdawanyPuesc
        import app as aplikacja
        cls.app = aplikacja
        cls.c = aplikacja.app.test_client()

    def test_caly_przeplyw(self):
        for u in ("/", "/nowe", "/ustawienia", "/log", "/dokumenty", "/eksport.csv"):
            self.assertEqual(self.c.get(u).status_code, 200, u)
        self.c.post("/ustawienia", data={"srodowisko": "test", "akcja": "zapisz", "login": "test@firma.pl",
                                         "haslo": "tajne", "endpoint": "", "target_systems": "", "ws_json": ""})
        r = self.c.post("/nowe", data={"tryb": "vin", "viny": VIN.lower() + "\n", "akcja": "wyslij"},
                        follow_redirects=True)
        self.assertIn("Wysłano 1 z 1", r.get_data(as_text=True))
        wyslany = etree.fromstring(UdawanyPuesc.wyslane[-1])
        tresc = base64.b64decode(wyslany.findtext(".//{%s}content" % seap.NS_TYPY))
        self.assertEqual(pzas.waliduj(tresc), [])
        self.assertIn(VIN.encode(), tresc)

        upp = b'<UPP xmlns="urn:upp"><InformacjaUzupelniajaca><KorelacjaSysref>SYS-123</KorelacjaSysref></InformacjaUzupelniajaca></UPP>'
        UdawanyPuesc.dokumenty = [("upp.xml", upp), ("pzas.xml", PRZYKLAD)]
        r = self.c.post("/sprawdz", follow_redirects=True)
        self.assertIn("Pobrano nowych dokumentów: 2", r.get_data(as_text=True))
        with self.app.app.app_context():
            z = self.app.db().execute("SELECT * FROM zapytania").fetchone()
        self.assertEqual(z["status"], "potwierdzone")
        self.assertEqual(z["doc_no"], "PZAS/0228/2021/00011")
        self.assertEqual(z["kwota_akcyzy"], "1550")
        pdf = self.c.get(f"/pdf/{z['id']}")
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b"%PDF"))
        pdf.close()
        self.assertEqual(self.c.get(f"/zapytanie/{z['id']}").status_code, 200)
        # ponowne sprawdzenie nie dubluje dokumentów
        r = self.c.post("/sprawdz", follow_redirects=True)
        self.assertIn("Pobrano nowych dokumentów: 0", r.get_data(as_text=True))
        log = list((Path(os.environ["ZEFIR_DATA"]) / "log").glob("*.txt"))
        self.assertTrue(log)
        self.assertNotIn(b"tajne", b"".join(p.read_bytes() for p in log))

    def test_npp_odrzuca(self):
        UdawanyPuesc.dokumenty = []
        self.c.post("/ustawienia", data={"srodowisko": "test", "akcja": "zapisz", "login": "test@firma.pl",
                                         "haslo": "tajne", "endpoint": "", "target_systems": "", "ws_json": ""})
        self.c.post("/nowe", data={"tryb": "vin", "viny": "TESTNPP0000000001", "akcja": "wyslij"})
        with self.app.app.app_context():
            zid = self.app.db().execute("SELECT id FROM zapytania WHERE vin='TESTNPP0000000001'").fetchone()["id"]
            self.app.db().execute("UPDATE zapytania SET sys_ref='SYS-NPP' WHERE id=?", (zid,))
            self.app.db().commit()
        npp = (b'<NPP xmlns="urn:npp"><KorelacjaSysref>SYS-NPP</KorelacjaSysref>'
               b'<OpisBledu>Dokument niepodpisany</OpisBledu></NPP>')
        UdawanyPuesc.dokumenty = [("npp.xml", npp)]
        self.c.post("/sprawdz", data={"id": zid})
        with self.app.app.app_context():
            z = self.app.db().execute("SELECT * FROM zapytania WHERE id=?", (zid,)).fetchone()
        self.assertEqual(z["status"], "odrzucone")
        self.assertIn("niepodpisany", z["opis"])


if __name__ == "__main__":
    unittest.main()
