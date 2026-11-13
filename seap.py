"""Klient kanału WebService SEAP/PUESC (WS_PULL, DocumentHandlingPort).

Na podstawie: SEAP PLUS – Specyfikacja Techniczna Publiczna PL, wersja 5.50.

- SOAP 1.1, WS-Addressing (wymagany MessageID), WS-Security UsernameToken / PasswordDigest:
      Password_Digest = Base64( SHA-1( nonce + created + Base64( SHA-1( hasło ) ) ) )
  Login = adres e-mail konta PUESC, wsu:Created w UTC (±5 min od czasu serwera).
- Operacje: AcceptDocument, GetNextDocument, GetNextDocumentSisc, GetDocuments.

Specyfikacja nie podaje przestrzeni nazw ani wartości Action, dlatego:
  1) są domyślne wartości (z dostępnych przykładów PUESC),
  2) można je wykryć z WSDL serwera (wykryj_z_wsdl),
  3) można je nadpisać ręcznie w ustawieniach aplikacji.
Odpowiedzi są czytane po nazwach lokalnych elementów, więc nie zależą od przestrzeni nazw.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from lxml import etree

NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
NS_WSA = "http://www.w3.org/2005/08/addressing"
PASSWORD_DIGEST = ("http://docs.oasis-open.org/wss/2004/01/"
                   "oasis-200401-wss-username-token-profile-1.0#PasswordDigest")
PASSWORD_TEXT = ("http://docs.oasis-open.org/wss/2004/01/"
                 "oasis-200401-wss-username-token-profile-1.0#PasswordText")
BASE64_BINARY = ("http://docs.oasis-open.org/wss/2004/01/"
                 "oasis-200401-wss-soap-message-security-1.0#Base64Binary")

ENDPOINTY = {
    "test": "https://te-ws.puesc.gov.pl/seap_wsChannel/DocumentHandlingPort",
    "produkcja": "https://ws.puesc.gov.pl/seap_wsChannel/DocumentHandlingPort",
}

# Przestrzenie nazw widoczne w przykładach/komunikatach PUESC (do nadpisania w ustawieniach).
NS_USLUGA = "http://www.mf.gov.pl/uslugiBiznesowe/WsPull/Usluga/2014/01_v2_0"
NS_TYPY = "http://www.mf.gov.pl/schematy/SISC/WsChannel/2014/01_v2_0"

OPERACJE = ["AcceptDocument", "GetNextDocument", "GetNextDocumentSisc", "GetDocuments"]

# Kolejność elementów żądania GetDocuments wg tabeli 12 specyfikacji SEAP (xs:sequence).
POLA_GET_DOCUMENTS = ["idSiscROF", "idSiscROP", "idSiscP", "sysRef", "korelacjaSysref", "idWysylki",
                      "idDocSysZew", "idSprawy", "dataOd", "dataDo", "pobrany", "targetSystem",
                      "allEmployees"]
POLA_GET_NEXT_SISC = ["idSiscROF", "idSiscROP", "idSiscP", "targetSystem", "allEmployees"]


class BladSeap(Exception):
    """Błąd komunikacji z SEAP (HTTP, SOAP Fault, nieczytelna odpowiedź)."""

    def __init__(self, komunikat: str, odpowiedz: str = ""):
        super().__init__(komunikat)
        self.odpowiedz = odpowiedz


# ---------------------------------------------------------------- WS-Security

def skrot_hasla(haslo: str) -> str:
    """Base64(SHA-1(hasło)) – tylko to jest przechowywane, nie samo hasło."""
    return base64.b64encode(hashlib.sha1(haslo.encode("utf-8")).digest()).decode("ascii")


def password_digest(nonce: bytes, created: str, skrot: str) -> str:
    h = hashlib.sha1(nonce + created.encode("utf-8") + skrot.encode("utf-8")).digest()
    return base64.b64encode(h).decode("ascii")


def teraz_utc(przesuniecie: float = 0.0, ms: bool = False) -> str:
    t = datetime.now(timezone.utc) + timedelta(seconds=przesuniecie)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + (f".{t.microsecond // 1000:03d}" if ms else "") + "Z"


# Wariant uwierzytelnienia WS-Security. Domyślny = wzór ze specyfikacji SEAP (skrót hasła).
#   haslo:     "skrot"    – digest liczony z Base64(SHA-1(hasło))  (specyfikacja PUESC)
#              "standard" – digest liczony z samego hasła          (standard OASIS)
#              "tekst"    – PasswordText (hasło jawnie, w HTTPS)
#   timestamp: dodaj wsu:Timestamp (Created/Expires) w nagłówku Security
#   nonce:     "bin" – do skrótu idą bajty nonce (standard), "b64" – tekst Base64 nonce
#   ms:        wsu:Created z milisekundami
DOMYSLNY_TRYB = {"haslo": "skrot", "timestamp": False, "nonce": "bin", "ms": False}

WARIANTY_DIAGNOSTYKI = [
    {"haslo": "skrot", "timestamp": False, "nonce": "bin", "ms": False},
    {"haslo": "skrot", "timestamp": True, "nonce": "bin", "ms": False},
    {"haslo": "skrot", "timestamp": False, "nonce": "bin", "ms": True},
    {"haslo": "standard", "timestamp": False, "nonce": "bin", "ms": False},
    {"haslo": "standard", "timestamp": True, "nonce": "bin", "ms": False},
    {"haslo": "skrot", "timestamp": False, "nonce": "b64", "ms": False},
    {"haslo": "tekst", "timestamp": False, "nonce": "bin", "ms": False},
    {"haslo": "tekst", "timestamp": True, "nonce": "bin", "ms": False},
]


def opis_trybu(t: dict) -> str:
    h = {"skrot": "digest ze skrótu hasła (PUESC)", "standard": "digest z hasła (standard)",
         "tekst": "hasło jawne (PasswordText)"}[t.get("haslo", "skrot")]
    return h + (" + Timestamp" if t.get("timestamp") else "") + \
        (" + nonce jako tekst" if t.get("nonce") == "b64" else "") + (" + ms w Created" if t.get("ms") else "")


# ---------------------------------------------------------------- konfiguracja

def domyslna_konfiguracja(srodowisko: str = "test") -> dict:
    return {
        "endpoint": ENDPOINTY.get(srodowisko, ENDPOINTY["test"]),
        "operacje": {op: {"element": f"{{{NS_USLUGA}}}{op}Request",
                          "akcja": op, "soap_action": op} for op in OPERACJE},
        "ns_typy": NS_TYPY,
        "zrodlo": "domyślne",
    }


def _qn(tekst: str, nsmap: dict, domyslny: str = "") -> str:
    """'tns:Nazwa' → '{ns}Nazwa' wg nsmap elementu."""
    if ":" in tekst:
        p, nazwa = tekst.split(":", 1)
        return f"{{{nsmap.get(p, '')}}}{nazwa}"
    return f"{{{nsmap.get(None, domyslny)}}}{tekst}"


def _lokalna(el) -> str:
    return etree.QName(el).localname if isinstance(el.tag, str) else ""


def wykryj_z_wsdl(endpoint: str, sesja: requests.Session | None = None, timeout: int = 30) -> dict:
    """Czyta WSDL (i importowane XSD) i ustala elementy żądań, akcje i przestrzeń nazw typów."""
    s = sesja or requests.Session()
    dokumenty: dict[str, etree._Element] = {}
    kolejka = [endpoint + "?wsdl"]
    while kolejka and len(dokumenty) < 15:
        url = kolejka.pop(0)
        if url in dokumenty:
            continue
        r = s.get(url, timeout=timeout)
        r.raise_for_status()
        root = etree.fromstring(r.content)
        dokumenty[url] = root
        for el in root.iter():
            if _lokalna(el) in ("import", "include"):
                loc = el.get("location") or el.get("schemaLocation")
                if loc:
                    kolejka.append(urljoin(url, loc))

    wsdl_ns = "http://schemas.xmlsoap.org/wsdl/"
    wiadomosci, akcje_wej, soap_akcje, element_nsy = {}, {}, {}, {}
    ns_typy = None
    for root in dokumenty.values():
        tns = root.get("targetNamespace", "")
        for msg in root.iter(f"{{{wsdl_ns}}}message"):
            part = msg.find(f"{{{wsdl_ns}}}part")
            if part is not None and part.get("element"):
                wiadomosci[f"{{{tns}}}{msg.get('name')}"] = _qn(part.get("element"), part.nsmap)
        for op in root.iter(f"{{{wsdl_ns}}}operation"):
            wej = op.find(f"{{{wsdl_ns}}}input")
            if wej is not None and wej.get("message"):
                akcja = next((v for k, v in wej.attrib.items() if etree.QName(k).localname == "Action"), None)
                akcje_wej[op.get("name")] = (_qn(wej.get("message"), wej.nsmap, tns), akcja)
            for sub in op:
                if _lokalna(sub) == "operation" and sub.get("soapAction") is not None:
                    soap_akcje[op.get("name")] = sub.get("soapAction")
        for sch in root.iter("{http://www.w3.org/2001/XMLSchema}schema"):
            stns, kwal = sch.get("targetNamespace", ""), sch.get("elementFormDefault") == "qualified"
            for el in sch:
                if _lokalna(el) in ("element", "complexType") and el.get("name"):
                    element_nsy[el.get("name")] = (stns, kwal)

    konf = {"endpoint": endpoint, "operacje": {}, "ns_typy": NS_TYPY, "zrodlo": "WSDL"}
    for op in OPERACJE:
        if op not in akcje_wej:
            continue
        msg, akcja = akcje_wej[op]
        element = wiadomosci.get(msg) or f"{{{NS_USLUGA}}}{op}Request"
        konf["operacje"][op] = {"element": element, "akcja": akcja or soap_akcje.get(op) or op,
                                "soap_action": soap_akcje.get(op, op)}
    if "documentType" in element_nsy:
        tns, kwal = element_nsy["documentType"]
        ns_typy = tns if kwal else ""
    elif konf["operacje"].get("AcceptDocument"):
        nazwa = etree.QName(konf["operacje"]["AcceptDocument"]["element"]).localname
        tns, kwal = element_nsy.get(nazwa, (NS_TYPY, True))
        ns_typy = tns if kwal else ""
    if ns_typy is not None:
        konf["ns_typy"] = ns_typy
    if not konf["operacje"]:
        raise BladSeap("W WSDL nie znaleziono operacji DocumentHandlingPort.")
    for op in OPERACJE:
        konf["operacje"].setdefault(op, domyslna_konfiguracja()["operacje"][op])
    return konf


# ---------------------------------------------------------------- odczyt odpowiedzi

def _tekst_dzieci(el) -> dict:
    """Proste pola (bez dzieci) elementu: nazwa lokalna → tekst."""
    out = {}
    for d in el:
        if isinstance(d.tag, str) and len(d) == 0:
            out[_lokalna(d)] = (d.text or "").strip()
    return out


def _b64(tekst: str | None) -> bytes:
    return base64.b64decode(re.sub(r"\s+", "", tekst or ""))


def parsuj_dokument(el) -> dict:
    """Element <document> z odpowiedzi → {'meta', 'filename', 'content', 'zalaczniki'}."""
    dok = {"meta": _tekst_dzieci(el), "filename": "", "content": b"", "zalaczniki": []}
    for d in el.iter():
        nazwa = _lokalna(d)
        if nazwa != "content":
            continue
        wartosc = next((x for x in d if _lokalna(x) == "value"), None)
        dane = _b64(wartosc.text if wartosc is not None else d.text)
        rodzic = d.getparent()
        if rodzic is not None and _lokalna(rodzic) == "attachments":
            dok["zalaczniki"].append({"filename": d.get("filename", ""), "mime": d.get("mime", ""),
                                      "content": dane})
        elif not dok["content"]:
            dok["filename"], dok["content"] = d.get("filename", ""), dane
    dok["meta"].pop("content", None)
    return dok


# ---------------------------------------------------------------- klient

class Klient:
    def __init__(self, konf: dict, login: str, skrot: str, log_dir: Path | None = None,
                 sesja: requests.Session | None = None, timeout: int = 90,
                 tryb: dict | None = None, haslo: str = "", przesuniecie: float = 0.0):
        self.tryb = {**DOMYSLNY_TRYB, **(tryb or {})}
        if not login or not (skrot or haslo):
            raise BladSeap("Brak loginu lub hasła PUESC – uzupełnij je w Ustawieniach.")
        if self.tryb["haslo"] != "skrot" and not haslo:
            raise BladSeap("Wybrany wariant logowania wymaga zapisanego hasła – wpisz je ponownie w Ustawieniach.")
        self.konf, self.login = konf, login.strip()
        self.skrot = skrot or skrot_hasla(haslo)
        self.haslo = haslo
        self.przesuniecie = przesuniecie  # sekundy: czas serwera − czas komputera (korekta zegara)
        self.log_dir, self.timeout = log_dir, timeout
        self.sesja = sesja or requests.Session()
        self.czas_serwera: datetime | None = None
        self.poprawiono_konf = False  # True, gdy konfiguracja została poprawiona na podstawie błędu serwera

    # -- koperta
    def koperta(self, op: str, pola: list[tuple[str, object]] | None = None,
                cialo: etree._Element | None = None) -> bytes:
        o = self.konf["operacje"][op]
        E = etree.Element
        env = E(f"{{{NS_SOAP}}}Envelope", nsmap={"soapenv": NS_SOAP, "wsa": NS_WSA})
        head = etree.SubElement(env, f"{{{NS_SOAP}}}Header")

        sec = etree.SubElement(head, f"{{{NS_WSSE}}}Security", nsmap={"wsse": NS_WSSE, "wsu": NS_WSU})
        sec.set(f"{{{NS_SOAP}}}mustUnderstand", "1")
        tok = etree.SubElement(sec, f"{{{NS_WSSE}}}UsernameToken")
        tok.set(f"{{{NS_WSU}}}Id", f"UsernameToken-{uuid.uuid4().hex}")
        t = self.tryb
        nonce, created = os.urandom(16), teraz_utc(self.przesuniecie, t["ms"])
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        if t["timestamp"]:
            ts = etree.Element(f"{{{NS_WSU}}}Timestamp")
            ts.set(f"{{{NS_WSU}}}Id", f"TS-{uuid.uuid4().hex}")
            etree.SubElement(ts, f"{{{NS_WSU}}}Created").text = created
            etree.SubElement(ts, f"{{{NS_WSU}}}Expires").text = teraz_utc(self.przesuniecie + 300, t["ms"])
            sec.insert(0, ts)
        etree.SubElement(tok, f"{{{NS_WSSE}}}Username").text = self.login
        if t["haslo"] == "tekst":
            etree.SubElement(tok, f"{{{NS_WSSE}}}Password", Type=PASSWORD_TEXT).text = self.haslo
        else:
            sekret = self.skrot if t["haslo"] == "skrot" else self.haslo
            n_do_skrotu = nonce_b64.encode("ascii") if t["nonce"] == "b64" else nonce
            pw = etree.SubElement(tok, f"{{{NS_WSSE}}}Password", Type=PASSWORD_DIGEST)
            pw.text = password_digest(n_do_skrotu, created, sekret)
        n = etree.SubElement(tok, f"{{{NS_WSSE}}}Nonce", EncodingType=BASE64_BINARY)
        n.text = nonce_b64
        etree.SubElement(tok, f"{{{NS_WSU}}}Created").text = created

        etree.SubElement(head, f"{{{NS_WSA}}}Action").text = o["akcja"]
        etree.SubElement(head, f"{{{NS_WSA}}}MessageID").text = f"urn:uuid:{uuid.uuid4()}"
        etree.SubElement(head, f"{{{NS_WSA}}}To").text = self.konf["endpoint"]

        body = etree.SubElement(env, f"{{{NS_SOAP}}}Body")
        wrap = etree.SubElement(body, o["element"])
        ns = self.ns_pol(op)
        for nazwa, wartosc in pola or []:
            if wartosc in (None, ""):
                continue
            el = etree.SubElement(wrap, f"{{{ns}}}{nazwa}" if ns else nazwa)
            el.text = str(wartosc).lower() if isinstance(wartosc, bool) else str(wartosc)
        if cialo is not None:
            wrap.append(cialo)
        return etree.tostring(env, xml_declaration=True, encoding="UTF-8")

    def ns_pol(self, op: str) -> str:
        """Przestrzeń nazw pól żądania (dzieci elementu *Request) – ta sama co element żądania.

        PUESC: pola GetDocuments (dataOd, pobrany, …) i element document są w przestrzeni usługi
        …/uslugiBiznesowe/WsPull/Usluga/2014/01_v2_0, a zawartość dokumentu (content, targetSystems)
        – w przestrzeni typów …/schematy/SISC/WsChannel/2014/01_v2_0 (ns_typy).
        """
        o = self.konf["operacje"][op]
        if "ns_pola" in o:
            return o["ns_pola"]
        return etree.QName(o["element"]).namespace or ""

    @staticmethod
    def _sub(rodzic, ns: str, nazwa: str, **attr) -> etree._Element:
        return etree.SubElement(rodzic, f"{{{ns}}}{nazwa}" if ns else nazwa, **attr)

    # -- transport
    def _loguj(self, op: str, zadanie: bytes, odpowiedz: bytes | str, status: int | str):
        if not self.log_dir:
            return
        self.log_dir.mkdir(parents=True, exist_ok=True)
        z = re.sub(rb"(<[\w:]*Password[^>]*>)[^<]*", rb"\1***", zadanie)
        z = re.sub(rb"(<[\w:]*Nonce[^>]*>)[^<]*", rb"\1***", z)
        z = re.sub(rb"(<[\w:]*content[^>]*>)([^<]{200})[^<]*", rb"\1\2...", z)
        o = odpowiedz.encode("utf-8", "replace") if isinstance(odpowiedz, str) else odpowiedz
        o = re.sub(rb"(<[\w:]*(?:content|value)[^>]*>)([^<]{200})[^<]*", rb"\1\2...", o)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        (self.log_dir / f"{stamp}_{op}.txt").write_bytes(
            b"=== ZADANIE " + op.encode() + b" -> " + self.konf["endpoint"].encode() + b"\n" + z +
            b"\n\n=== ODPOWIEDZ (HTTP " + str(status).encode() + b")\n" + o + b"\n")

    def wyslij(self, op: str, koperta: bytes) -> etree._Element:
        o = self.konf["operacje"][op]
        try:
            r = self.sesja.post(self.konf["endpoint"], data=koperta, timeout=self.timeout, headers={
                "Content-Type": "text/xml; charset=utf-8", "SOAPAction": f'"{o["soap_action"]}"'})
        except requests.RequestException as e:
            self._loguj(op, koperta, str(e), "brak")
            raise BladSeap(f"Brak połączenia z PUESC: {e}") from e
        self._loguj(op, koperta, r.content, r.status_code)
        try:
            self.czas_serwera = parsedate_to_datetime(r.headers.get("Date", "")) if getattr(r, "headers", None) else None
        except (TypeError, ValueError):
            self.czas_serwera = None
        try:
            root = etree.fromstring(r.content)
        except etree.XMLSyntaxError:
            raise BladSeap(f"PUESC zwrócił HTTP {r.status_code} bez poprawnego XML.", r.text[:2000])
        body = next((el for el in root.iter() if _lokalna(el) == "Body"), None)
        if body is None or len(body) == 0:
            raise BladSeap(f"Odpowiedź bez treści SOAP (HTTP {r.status_code}).", r.text[:2000])
        wynik = body[0]
        if _lokalna(wynik) == "Fault":
            pola = {_lokalna(x): (x.text or "").strip() for x in wynik.iter() if len(x) == 0}
            raise BladSeap(f"SOAP Fault: {pola.get('faultstring') or pola.get('Text') or pola}",
                           r.text[:4000])
        if r.status_code >= 400:
            raise BladSeap(f"PUESC zwrócił HTTP {r.status_code}.", r.text[:2000])
        return wynik

    # -- samonaprawa przestrzeni nazw
    POLA_DOKUMENTU = {"content", "attachments", "targetSystems", "system", "value"}

    def popraw_z_bledu(self, op: str, e: BladSeap) -> bool:
        """'Unmarshalling Error: unexpected element (uri:"A", local:"x"). Expected elements are <{B}y>…'
        → przenieś element x do przestrzeni B. Zwraca True, jeśli coś poprawiono."""
        m = re.search(r'unexpected element \(uri:"([^"]*)", local:"([^"]+)"\)', str(e))
        oczek = re.findall(r"<\{([^}]*)\}(\w+)>", str(e))
        if not m or not oczek:
            return False
        lokalna = m.group(2)
        ns = next((n for n, nazwa in oczek if nazwa == lokalna), oczek[0][0])
        if ns == m.group(1):
            return False
        if lokalna in self.POLA_DOKUMENTU:
            if self.konf.get("ns_typy") == ns:
                return False
            self.konf["ns_typy"] = ns
        else:
            if self.ns_pol(op) == ns:
                return False
            self.konf["operacje"][op]["ns_pola"] = ns
        self.poprawiono_konf = True
        return True

    def _z_poprawka(self, op: str, wywolanie):
        for proba in range(3):  # najwyżej dwie poprawki (pola żądania + zawartość dokumentu)
            try:
                return wywolanie()
            except BladSeap as e:
                if proba == 2 or not self.popraw_z_bledu(op, e):
                    raise

    # -- operacje
    def accept_document(self, xml: bytes, filename: str, target_systems: list[str] | None = None) -> dict:
        return self._z_poprawka("AcceptDocument", lambda: self._accept_document(xml, filename, target_systems))

    def _accept_document(self, xml: bytes, filename: str, target_systems: list[str] | None = None) -> dict:
        ns_p, ns_t = self.ns_pol("AcceptDocument"), self.konf.get("ns_typy", "")
        doc = etree.Element(f"{{{ns_p}}}document" if ns_p else "document")
        c = self._sub(doc, ns_t, "content", filename=filename[:128], mime="application/xml")
        c.text = base64.b64encode(xml).decode("ascii")
        if target_systems:
            ts = self._sub(doc, ns_t, "targetSystems")
            for s in target_systems:
                self._sub(ts, ns_t, "system").text = s
        wynik = self.wyslij("AcceptDocument", self.koperta("AcceptDocument", cialo=doc))
        result = next((el for el in wynik.iter() if _lokalna(el) == "result"), wynik)
        pola = {_lokalna(x): (x.text or "").strip() for x in result.iter() if len(x) == 0 and x is not result}
        if not pola.get("sysRef"):
            raise BladSeap(f"PUESC nie zwrócił sysRef: {pola or 'pusta odpowiedź'}")
        return pola

    def get_documents(self, **filtry) -> list[dict]:
        pola = [(k, filtry.get(k)) for k in POLA_GET_DOCUMENTS]
        wynik = self._z_poprawka("GetDocuments",
                                 lambda: self.wyslij("GetDocuments", self.koperta("GetDocuments", pola)))
        return [parsuj_dokument(el) for el in wynik.iter() if _lokalna(el) == "document"]

    def get_next_document(self, sisc: bool = False, **filtry) -> tuple[dict | None, bool]:
        op = "GetNextDocumentSisc" if sisc else "GetNextDocument"
        pola = [(k, filtry.get(k)) for k in (POLA_GET_NEXT_SISC if sisc else ["targetSystem"])]
        wynik = self._z_poprawka(op, lambda: self.wyslij(op, self.koperta(op, pola)))
        dok = next((el for el in wynik.iter() if _lokalna(el) == "document"), None)
        has_next = next((el.text for el in wynik.iter() if _lokalna(el) == "hasNext"), "false")
        return (parsuj_dokument(dok) if dok is not None else None), (has_next or "").strip() == "true"


def jest_bledem_logowania(e: Exception) -> bool:
    return bool(re.search(r"security|WSSecurity|authenticat|unauthori|HTTP 401|HTTP 403", str(e), re.I))


def diagnozuj(konf: dict, login: str, haslo: str, log_dir: Path | None = None,
              sesja: requests.Session | None = None) -> dict:
    """Sprawdza warianty logowania jedną, niczego nie zmieniającą operacją (GetDocuments za dziś).

    Zwraca {'proby': [(tryb, ok, komunikat)], 'dzialajacy': tryb|None, 'przesuniecie': s, 'czas_serwera': str}.
    """
    from datetime import date
    s = sesja or requests.Session()
    dzis = date.today().isoformat()
    wynik = {"proby": [], "dzialajacy": None, "przesuniecie": 0.0, "czas_serwera": ""}
    przes = 0.0
    for i, tryb in enumerate(WARIANTY_DIAGNOSTYKI):
        k = Klient(konf, login, "", log_dir=log_dir, sesja=s, timeout=60, tryb=tryb, haslo=haslo,
                   przesuniecie=przes)
        try:
            n = len(k.get_documents(dataOd=dzis, dataDo=dzis, pobrany=0))
            wynik["proby"].append((tryb, True, f"OK – dokumentów z dziś: {n}"))
            wynik["dzialajacy"] = tryb
        except BladSeap as e:
            wynik["proby"].append((tryb, False, str(e)))
            if not jest_bledem_logowania(e) and "Brak połączenia" in str(e):
                break  # brak sieci – dalsze próby nic nie dadzą
        if i == 0 and k.czas_serwera:
            przes = (k.czas_serwera - datetime.now(timezone.utc)).total_seconds()
            wynik["przesuniecie"] = przes
            wynik["czas_serwera"] = k.czas_serwera.isoformat()
            if abs(przes) < 60:
                przes = 0.0  # zegar w porządku – nie korygujemy
        if wynik["dzialajacy"]:
            break
    wynik["przesuniecie_uzyte"] = przes
    return wynik
