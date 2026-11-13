"""Komunikaty ZEFIR2 PZAS – zapytanie i odpowiedź „potwierdzenie zapłaty akcyzy za samochód”.

Źródło: ZF2-PWT-KXML-PZAS_v2.0 (obowiązuje od 01.07.2021), schematy w folderze schematy/:
  PZASReq.xsd  – namespace http://www.e-clo.pl/ZEFIR2/eZefir2/xsd/v2_0/PZASReq.xsd, wersja 2_0
  PZASResp.xsd – namespace http://www.e-clo.pl/ZEFIR2/eZefir2/xsd/v4_0/pzas_resp.xsd, wersja 4_0
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from lxml import etree

NS_REQ = "http://www.e-clo.pl/ZEFIR2/eZefir2/xsd/v2_0/PZASReq.xsd"
WERSJA_REQ = "2_0"
SCHEMATY = Path(__file__).resolve().parent / "schematy"

WARIANTY = {
    "1": "Nabycie wewnątrzwspólnotowe samochodu osobowego niezarejestrowanego wcześniej w kraju",
    "2": "Zmiany konstrukcyjne zmieniające rodzaj pojazdu na samochód osobowy",
    "3": "Nabycie lub posiadanie samochodu niezarejestrowanego w kraju – nie ustalono wcześniejszego podmiotu",
}

# Potwierdzenia techniczne SEAP/SISC (nazwy elementów głównych, porównywane bez wielkości liter).
TECHNICZNE = {
    "upp": "UPP – poświadczenie przedłożenia (PUESC)",
    "npp": "NPP – dokument nie został przyjęty (PUESC)",
    "upd": "UPD – poświadczenie doręczenia (wymaga podpisania)",
    "npd": "NPD – poświadczenie niedoręczenia",
    "pnd": "PND – poświadczenie niedoręczenia",
    "upo": "UPO – urzędowe poświadczenie odbioru",
    "potwierdzenie": "UPO – urzędowe poświadczenie odbioru (ZEFIR2)",
    "info": "INFO – informacja z ZEFIR2",
}

_schematy: dict[str, etree.XMLSchema] = {}


def schemat(nazwa: str) -> etree.XMLSchema:
    if nazwa not in _schematy:
        _schematy[nazwa] = etree.XMLSchema(etree.parse(str(SCHEMATY / nazwa)))
    return _schematy[nazwa]


def normalizuj_vin(vin: str) -> str:
    return re.sub(r"[\s-]+", "", vin or "").upper()


def zbuduj_zapytanie(vin: str | None = None, upo: str | None = None, zbiorcze: bool = False,
                     kwota: int | str | None = None, self_ref: str | None = None) -> bytes:
    """PZASReq. Wymagany VIN albo numer UPO deklaracji (np. AKC-US)."""
    vin, upo = normalizuj_vin(vin or ""), (upo or "").strip()
    if not vin and not upo:
        raise ValueError("Podaj VIN albo numer UPO deklaracji.")
    root = etree.Element(f"{{{NS_REQ}}}PZASReq", nsmap={None: NS_REQ}, version=WERSJA_REQ)
    if self_ref:
        root.set("selfRef", self_ref)
    etree.SubElement(root, f"{{{NS_REQ}}}collective").text = "true" if zbiorcze else "false"
    if vin:
        etree.SubElement(root, f"{{{NS_REQ}}}VIN").text = vin
    if upo:
        etree.SubElement(root, f"{{{NS_REQ}}}UPONumber").text = upo
    if kwota not in (None, ""):
        etree.SubElement(root, f"{{{NS_REQ}}}docAmount").text = str(int(str(kwota).replace(" ", "")))
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def waliduj(xml: bytes, nazwa_xsd: str = "PZASReq.xsd") -> list[str]:
    s = schemat(nazwa_xsd)
    try:
        dok = etree.fromstring(xml)
    except etree.XMLSyntaxError as e:
        return [str(e)]
    if s.validate(dok):
        return []
    return [f"linia {e.line}: {e.message}" for e in s.error_log]


def _lok(el) -> str:
    return etree.QName(el).localname if isinstance(el.tag, str) else ""


def rodzaj(xml: bytes) -> str:
    """Nazwa lokalna elementu głównego (PZASResp, UPP, NPP, Potwierdzenie, …)."""
    try:
        return _lok(etree.fromstring(xml))
    except etree.XMLSyntaxError:
        return "nie-XML"


def opis_rodzaju(r: str) -> str:
    if r == "PZASResp":
        return "PZASResp – odpowiedź z potwierdzeniem zapłaty akcyzy"
    return TECHNICZNE.get(r.lower(), r)


def parsuj_odpowiedz(xml: bytes) -> dict:
    root = etree.fromstring(xml)
    if _lok(root) != "PZASResp":
        raise ValueError(f"To nie jest PZASResp, tylko {_lok(root)}.")

    def t(el, nazwa):
        x = next((c for c in el if _lok(c) == nazwa), None)
        return (x.text or "").strip() if x is not None else ""

    przedmiot = next((c for c in root if _lok(c) == "subjectOfTaxation"), None)
    wariant = przedmiot.get("optionSubjectOfTaxation", "") if przedmiot is not None else ""
    if przedmiot is not None and not wariant:
        wariant = t(przedmiot, "optionSubjectOfTaxation")
    auta = []
    for c in root:
        if _lok(c) == "car":
            auta.append({k: t(c, k) for k in ("no", "dateOfPayment", "VIN", "makeModel", "capacity",
                                              "exciseAmount", "yearOfProduction", "condition")})
            auta[-1]["dateOfPayment"] = auta[-1]["dateOfPayment"][:10]
    doc = t(root, "doc")
    return {
        "docNo": t(root, "docNo"), "dateOfIssue": t(root, "dateOfIssue"),
        "organ": t(root, "nameOfTheTaxAuthority"), "wariant": wariant,
        "wariant_opis": WARIANTY.get(wariant, ""), "auta": auta,
        "komunikaty": [(c.text or "").strip() for c in root if _lok(c) == "message" and c.text],
        "pdf": base64.b64decode(re.sub(r"\s+", "", doc)) if doc else None,
    }


def parsuj_techniczne(xml: bytes) -> dict:
    """UPP/NPP/UPD/UPO… – pola liściowe (bez podpisów i stempli) oraz KorelacjaSysref."""
    root = etree.fromstring(xml)
    pola: dict[str, str] = {}
    for el in root.iter():
        if not isinstance(el.tag, str) or len(el) or not (el.text or "").strip():
            continue
        ns = etree.QName(el).namespace or ""
        if "xmldsig" in ns or "xades" in ns.lower():
            continue
        nazwa = _lok(el)
        if nazwa in ("StempelCzasu", "SkrotDokumentu", "SkrotZlozonejStruktury"):
            continue
        tekst = el.text.strip()
        pola[nazwa] = tekst if nazwa not in pola else f"{pola[nazwa]}; {tekst}"
    korelacja = next((v for k, v in pola.items() if k.lower() == "korelacjasysref"), "")
    return {"rodzaj": _lok(root), "pola": pola, "korelacja": korelacja}
