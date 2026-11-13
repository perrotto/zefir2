"""Potwierdzenia zapłaty akcyzy za samochód z ZEFIR2 (komunikat PZAS) przez WebService PUESC.

Uruchomienie:  python app.py   →  http://127.0.0.1:5010
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   send_file, url_for)

import pzas
import seap

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("ZEFIR_DATA", BASE / "data"))
DB_PATH = DATA / "zefir2.sqlite"
PDF_DIR = DATA / "potwierdzenia"
DOK_DIR = DATA / "dokumenty"
LOG_DIR = DATA / "log"

app = Flask(__name__)
app.secret_key = "zefir2-lokalnie"

SCHEMA = """
CREATE TABLE IF NOT EXISTS ustawienia (klucz TEXT PRIMARY KEY, wartosc TEXT);
CREATE TABLE IF NOT EXISTS zapytania (
    id INTEGER PRIMARY KEY, utworzono TEXT DEFAULT CURRENT_TIMESTAMP, srodowisko TEXT,
    vin TEXT, upo TEXT, zbiorcze INTEGER DEFAULT 0, kwota TEXT, plik TEXT,
    sys_ref TEXT, status TEXT DEFAULT 'nowe', opis TEXT DEFAULT '',
    doc_no TEXT, data_zaplaty TEXT, kwota_akcyzy TEXT, marka_model TEXT, organ TEXT, pdf TEXT,
    sprawdzono TEXT, uwagi TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS dokumenty (
    id INTEGER PRIMARY KEY, zapytanie_id INTEGER REFERENCES zapytania(id) ON DELETE SET NULL,
    pobrano TEXT DEFAULT CURRENT_TIMESTAMP, rodzaj TEXT, plik TEXT, skrot TEXT UNIQUE,
    meta TEXT, opis TEXT);
"""

STATUSY = {
    "nowe": ("Nie wysłane", "due"),
    "blad": ("Błąd wysyłki", "late"),
    "wyslane": ("Wysłane – czeka", "part"),
    "przyjete": ("Przyjęte – czeka", "part"),
    "odrzucone": ("Odrzucone", "late"),
    "odpowiedz": ("Odpowiedź bez potwierdzenia", "due"),
    "potwierdzone": ("Potwierdzone", "ok"),
}
CZEKAJACE = ("wyslane", "przyjete")


# ---------------------------------------------------------------- baza

def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def _close(_exc):
    c = g.pop("db", None)
    if c:
        c.close()


def init_db():
    for d in (DATA, PDF_DIR, DOK_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)
    c.commit()
    c.close()


def ustawienie(klucz, domyslna=""):
    r = db().execute("SELECT wartosc FROM ustawienia WHERE klucz=?", (klucz,)).fetchone()
    return r["wartosc"] if r and r["wartosc"] is not None else domyslna


def zapisz_ustawienie(klucz, wartosc):
    db().execute("INSERT INTO ustawienia (klucz, wartosc) VALUES (?, ?) "
                 "ON CONFLICT(klucz) DO UPDATE SET wartosc=excluded.wartosc", (klucz, wartosc))


def srodowisko() -> str:
    return ustawienie("srodowisko", "produkcja")


_PROBY_WSDL: dict[tuple[str, str], str] = {}  # (środowisko, adres) → błąd ostatniej próby w tym uruchomieniu


def odczytaj_wsdl(sr: str, endpoint: str, wymus: bool = False) -> dict | None:
    """Pobiera konfigurację SOAP z WSDL serwera i zapisuje ją. Bez wymus – najwyżej raz na uruchomienie."""
    if not wymus and (sr, endpoint) in _PROBY_WSDL:
        return None
    try:
        konf = seap.wykryj_z_wsdl(endpoint)
    except Exception as e:  # brak sieci, zły adres, nieznany format WSDL
        _PROBY_WSDL[(sr, endpoint)] = str(e)
        return None
    _PROBY_WSDL.pop((sr, endpoint), None)
    zapisz_ustawienie(f"ws_{sr}", json.dumps(konf, ensure_ascii=False))
    db().commit()
    return konf


def konfiguracja_ws(auto_wsdl: bool = False) -> dict:
    """Konfiguracja SOAP: zapisana (z WSDL albo ręczna), a jeśli jej brak – próba odczytu z WSDL."""
    sr = srodowisko()
    endpoint = ustawienie(f"endpoint_{sr}") or seap.ENDPOINTY[sr]
    zapis = ustawienie(f"ws_{sr}")
    konf = json.loads(zapis) if zapis else None
    if konf is None and auto_wsdl:
        konf = odczytaj_wsdl(sr, endpoint)
    konf = konf or seap.domyslna_konfiguracja(sr)
    konf["endpoint"] = endpoint
    return konf


def tryb_logowania(sr: str | None = None) -> dict:
    zapis = ustawienie(f"tryb_{sr or srodowisko()}")
    return {**seap.DOMYSLNY_TRYB, **(json.loads(zapis) if zapis else {})}


def klient() -> seap.Klient:
    sr = srodowisko()
    return seap.Klient(konfiguracja_ws(auto_wsdl=True), ustawienie(f"login_{sr}"),
                       ustawienie(f"skrot_{sr}"), log_dir=LOG_DIR, tryb=tryb_logowania(sr),
                       haslo=ustawienie(f"haslo_{sr}"),
                       przesuniecie=float(ustawienie(f"korekta_{sr}", "0") or 0))


def test_polaczenia() -> tuple[bool, str]:
    """GetDocuments za dzisiaj – niczego nie wysyła i nie oznacza dokumentów jako pobranych."""
    try:
        dzis = date.today().isoformat()
        n = len(klient().get_documents(dataOd=dzis, dataDo=dzis, pobrany=0))
        return True, f"Połączenie z PUESC ({srodowisko()}) działa – dzisiejszych dokumentów na koncie: {n}."
    except seap.BladSeap as e:
        rada = (" Uruchom „Diagnostykę logowania” w Ustawieniach – sprawdzi hasło, zegar i warianty podpisu."
                if seap.jest_bledem_logowania(e) else "")
        return False, f"Test połączenia z PUESC ({srodowisko()}) nieudany: {e}.{rada}"


def systemy_docelowe() -> list[str]:
    return [s.strip() for s in ustawienie("target_systems").split(",") if s.strip()]


# ---------------------------------------------------------------- szablony

@app.template_filter("dt")
def _dt(s):
    if not s:
        return "—"
    s = str(s)
    if re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", s):  # CURRENT_TIMESTAMP z SQLite = UTC
        s = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone() \
            .strftime("%Y-%m-%d %H:%M:%S")
    s = s.replace("T", " ")
    try:
        y, m, d = s[:10].split("-")
    except ValueError:
        return s
    return f"{d}.{m}.{y}" + (f" {s[11:16]}" if len(s) > 10 else "")


@app.template_filter("zl")
def _zl(x):
    if x in (None, ""):
        return "—"
    try:
        v = float(x)
    except ValueError:
        return x
    return f"{v:,.2f}".replace(",", " ").replace(".", ",")


@app.context_processor
def _ctx():
    sr = srodowisko()
    czeka = db().execute(f"SELECT COUNT(*) FROM zapytania WHERE status IN {CZEKAJACE}").fetchone()[0]
    return {"srodowisko": sr, "czeka": czeka, "STATUSY": STATUSY,
            "skonfigurowane": bool(ustawienie(f"login_{sr}") and ustawienie(f"skrot_{sr}"))}


# ---------------------------------------------------------------- logika

def zapisz_plik(katalog: Path, nazwa: str, dane: bytes) -> str:
    nazwa = re.sub(r"[^\w.\-]+", "_", nazwa)[:120]
    p = katalog / nazwa
    i = 1
    while p.exists():
        p = katalog / f"{p.stem}_{i}{p.suffix}"
        i += 1
    p.write_bytes(dane)
    return p.name


def wyslij_zapytanie(zid: int) -> bool:
    z = db().execute("SELECT * FROM zapytania WHERE id=?", (zid,)).fetchone()
    xml = (DOK_DIR / z["plik"]).read_bytes()
    try:
        wynik = klient().accept_document(xml, z["plik"], systemy_docelowe())
    except seap.BladSeap as e:
        opis = str(e) + (" – PUESC nie przyjął logowania; uruchom Diagnostykę logowania w Ustawieniach."
                         if seap.jest_bledem_logowania(e) else "")
        db().execute("UPDATE zapytania SET status='blad', opis=? WHERE id=?", (opis, zid))
        db().commit()
        return False
    db().execute("UPDATE zapytania SET status='wyslane', sys_ref=?, opis=?, srodowisko=? WHERE id=?",
                 (wynik["sysRef"], ", ".join(f"{k}: {v}" for k, v in wynik.items() if k != "sysRef"),
                  srodowisko(), zid))
    db().commit()
    return True


def dopasuj_zapytanie(rodzaj: str, xml: bytes, meta: dict, wskazane: int | None) -> int | None:
    if wskazane:
        return wskazane
    kor = meta.get("korelacjaSysref") or meta.get("KorelacjaSysref")
    if not kor and rodzaj != "PZASResp":
        try:
            kor = pzas.parsuj_techniczne(xml)["korelacja"]
        except Exception:
            kor = ""
    if kor:
        r = db().execute("SELECT id FROM zapytania WHERE sys_ref=?", (kor,)).fetchone()
        if r:
            return r["id"]
    if rodzaj == "PZASResp":
        try:
            vins = [a["VIN"] for a in pzas.parsuj_odpowiedz(xml)["auta"]]
        except Exception:
            vins = []
        for vin in vins:
            r = db().execute("SELECT id FROM zapytania WHERE vin=? AND status IN ('wyslane','przyjete') "
                             "ORDER BY id DESC LIMIT 1", (vin,)).fetchone()
            if r:
                return r["id"]
        r = db().execute("SELECT id FROM zapytania WHERE upo IS NOT NULL AND upo<>'' "
                         "AND status IN ('wyslane','przyjete')").fetchall()
        if len(r) == 1:
            return r[0]["id"]
    return None


def przetworz_dokument(dok: dict, zid: int | None = None) -> str | None:
    """Zapisuje dokument z PUESC (bez duplikatów) i aktualizuje zapytanie. Zwraca rodzaj albo None."""
    xml = dok["content"]
    if not xml:
        return None
    skrot = hashlib.sha1(xml).hexdigest()
    if db().execute("SELECT 1 FROM dokumenty WHERE skrot=?", (skrot,)).fetchone():
        return None
    rodzaj = pzas.rodzaj(xml)
    zid = dopasuj_zapytanie(rodzaj, xml, dok["meta"], zid)
    plik = zapisz_plik(DOK_DIR, f"{datetime.now():%Y%m%d-%H%M%S}_{rodzaj}_{dok['filename'] or 'dokument.xml'}", xml)
    opis = pzas.opis_rodzaju(rodzaj)
    nowy_status, opis_zap, dane = None, None, {}

    if rodzaj == "PZASResp":
        o = pzas.parsuj_odpowiedz(xml)
        opis_zap = " ".join(o["komunikaty"])
        dane = {"doc_no": o["docNo"], "organ": o["organ"]}
        if o["auta"]:
            a = o["auta"][0]
            dane.update(data_zaplaty=a["dateOfPayment"], kwota_akcyzy=a["exciseAmount"],
                        marka_model=a["makeModel"] + (f" (+{len(o['auta']) - 1} aut)" if len(o["auta"]) > 1 else ""))
            if zid:
                r = db().execute("SELECT vin FROM zapytania WHERE id=?", (zid,)).fetchone()
                if r and not r["vin"]:
                    dane["vin"] = ", ".join(x["VIN"] for x in o["auta"])
        if o["pdf"]:
            nazwa = (o["auta"][0]["VIN"] if o["auta"] else "potwierdzenie") + "_" + (o["docNo"] or "PZAS")
            dane["pdf"] = zapisz_plik(PDF_DIR, nazwa + ".pdf", o["pdf"])
        nowy_status = "potwierdzone" if o["auta"] and o["pdf"] else "odpowiedz"
    else:
        t = pzas.parsuj_techniczne(xml) if rodzaj != "nie-XML" else {"pola": {}}
        szczegoly = "; ".join(f"{k}: {v}" for k, v in t["pola"].items()
                              if re.search(r"opis|blad|błąd|kod|komunikat|przyczyn|uwag|przyjeto", k, re.I))
        if szczegoly:
            opis += f" – {szczegoly}"
        r = rodzaj.lower()
        if r == "npp" or t["pola"].get("Przyjeto") == "false":
            nowy_status, opis_zap = "odrzucone", opis
        elif r in ("upp", "upo", "potwierdzenie"):
            nowy_status = "przyjete"
        elif r == "upd":
            opis_zap = "Otrzymano UPD – podpisz je i odeślij na PUESC (inaczej po 14 dniach powstanie PND)."

    db().execute("INSERT INTO dokumenty (zapytanie_id, rodzaj, plik, skrot, meta, opis) VALUES (?,?,?,?,?,?)",
                 (zid, rodzaj, plik, skrot, json.dumps(dok["meta"], ensure_ascii=False), opis))
    if zid:
        obecny = db().execute("SELECT status FROM zapytania WHERE id=?", (zid,)).fetchone()["status"]
        if nowy_status == "przyjete" and obecny != "wyslane":
            nowy_status = None  # nie cofaj statusu, gdy odpowiedź już jest
        for k, v in dane.items():
            db().execute(f"UPDATE zapytania SET {k}=? WHERE id=?", (v, zid))
        if nowy_status:
            db().execute("UPDATE zapytania SET status=? WHERE id=?", (nowy_status, zid))
        if opis_zap:
            db().execute("UPDATE zapytania SET opis=? WHERE id=?", (opis_zap, zid))
    for z in dok.get("zalaczniki", []):
        if z["content"]:
            zapisz_plik(DOK_DIR, f"{datetime.now():%Y%m%d-%H%M%S}_zal_{z['filename'] or 'zalacznik'}", z["content"])
    db().commit()
    return rodzaj


def sprawdz_odpowiedzi(tylko: int | None = None) -> tuple[int, list[str]]:
    """GetDocuments po korelacji sysRef dla czekających zapytań + przegląd nowych dokumentów."""
    k = klient()
    nowe, bledy = 0, []
    warunek = "id=?" if tylko else f"status IN {CZEKAJACE}"
    zap = db().execute(f"SELECT id, sys_ref FROM zapytania WHERE {warunek} AND sys_ref IS NOT NULL",
                       (tylko,) if tylko else ()).fetchall()
    for z in zap:
        try:
            for dok in k.get_documents(korelacjaSysref=z["sys_ref"], pobrany=0):
                nowe += przetworz_dokument(dok, z["id"]) is not None
        except seap.BladSeap as e:
            bledy.append(f"Zapytanie #{z['id']}: {e}")
        db().execute("UPDATE zapytania SET sprawdzono=CURRENT_TIMESTAMP WHERE id=?", (z["id"],))
    if not tylko:
        try:
            dzis = date.today()
            for dok in k.get_documents(dataOd=(dzis - timedelta(days=9)).isoformat(),
                                       dataDo=dzis.isoformat(), pobrany=2):
                nowe += przetworz_dokument(dok) is not None
        except seap.BladSeap as e:
            bledy.append(f"Nowe dokumenty: {e}")
    db().commit()
    return nowe, bledy


# ---------------------------------------------------------------- widoki

@app.route("/")
def lista():
    status = request.args.get("status", "")
    szukaj = request.args.get("q", "").strip().upper()
    q, p = "SELECT * FROM zapytania WHERE 1=1", []
    if status:
        q += " AND status=?"
        p.append(status)
    if szukaj:
        q += " AND (UPPER(vin) LIKE ? OR UPPER(upo) LIKE ? OR UPPER(doc_no) LIKE ?)"
        p += [f"%{szukaj}%"] * 3
    zap = db().execute(q + " ORDER BY id DESC LIMIT 500", p).fetchall()
    licz = dict(db().execute("SELECT status, COUNT(*) FROM zapytania GROUP BY status").fetchall())
    return render_template("lista.html", zapytania=zap, status=status, q=szukaj, licz=licz)


@app.route("/nowe", methods=["GET", "POST"])
def nowe():
    if request.method == "POST":
        tryb = request.form.get("tryb", "vin")
        wyslac = request.form.get("akcja") == "wyslij"
        pozycje = []
        if tryb == "vin":
            vins = [pzas.normalizuj_vin(v) for v in re.split(r"[\n,;]+", request.form.get("viny", ""))]
            pozycje = [{"vin": v} for v in dict.fromkeys(v for v in vins if v)]
        else:
            upo = request.form.get("upo", "").strip()
            if upo:
                pozycje = [{"upo": upo, "zbiorcze": bool(request.form.get("zbiorcze")),
                            "kwota": request.form.get("kwota", "").replace(" ", "") or None}]
        if not pozycje:
            flash("Wpisz co najmniej jeden VIN albo numer UPO.", "err")
            return redirect(url_for("nowe"))
        if wyslac and not _ctx()["skonfigurowane"]:
            flash("Najpierw uzupełnij login i hasło PUESC w Ustawieniach.", "err")
            return redirect(url_for("ustawienia"))
        ok, zle = 0, []
        for poz in pozycje:
            try:
                xml = pzas.zbuduj_zapytanie(**poz)
            except ValueError as e:
                zle.append(str(e))
                continue
            bledy = pzas.waliduj(xml)
            if bledy:
                zle.append(f"{poz.get('vin') or poz.get('upo')}: {'; '.join(bledy)}")
                continue
            plik = zapisz_plik(DOK_DIR, f"PZASReq_{poz.get('vin') or poz.get('upo')}.xml", xml)
            cur = db().execute("INSERT INTO zapytania (srodowisko, vin, upo, zbiorcze, kwota, plik) "
                               "VALUES (?,?,?,?,?,?)", (srodowisko(), poz.get("vin"), poz.get("upo"),
                                                       1 if poz.get("zbiorcze") else 0, poz.get("kwota"), plik))
            db().commit()
            if wyslac:
                ok += wyslij_zapytanie(cur.lastrowid)
        if zle:
            flash("Pominięto: " + " | ".join(zle), "err")
        if wyslac:
            n = len(pozycje) - len(zle)
            flash(f"Wysłano {ok} z {n} zapytań." + (" Sprawdź błędy na liście." if ok < n else
                  " Odpowiedzi pobierzesz przyciskiem „Sprawdź odpowiedzi” (najlepiej po kilku minutach)."),
                  "ok" if ok == n else "warn")
        else:
            flash(f"Przygotowano {len(pozycje) - len(zle)} plików XML (nie wysłano).", "ok")
        return redirect(url_for("lista"))
    return render_template("nowe.html")


@app.route("/sprawdz", methods=["POST"])
def sprawdz():
    tylko = request.form.get("id", type=int)
    try:
        nowe_dok, bledy = sprawdz_odpowiedzi(tylko)
    except seap.BladSeap as e:
        flash(str(e), "err")
        return redirect(request.referrer or url_for("lista"))
    for b in bledy:
        flash(b, "err")
    flash(f"Pobrano nowych dokumentów: {nowe_dok}.", "ok" if nowe_dok else "warn")
    return redirect(url_for("zapytanie", zid=tylko) if tylko else url_for("lista"))


@app.route("/zapytanie/<int:zid>")
def zapytanie(zid):
    z = db().execute("SELECT * FROM zapytania WHERE id=?", (zid,)).fetchone() or abort(404)
    dok = db().execute("SELECT * FROM dokumenty WHERE zapytanie_id=? ORDER BY id", (zid,)).fetchall()
    odp = None
    for d in dok:
        if d["rodzaj"] == "PZASResp":
            odp = pzas.parsuj_odpowiedz((DOK_DIR / d["plik"]).read_bytes())
    return render_template("zapytanie.html", z=z, dokumenty=dok, odp=odp,
                           xml=(DOK_DIR / z["plik"]).read_text("utf-8") if z["plik"] else "")


@app.route("/zapytanie/<int:zid>/wyslij", methods=["POST"])
def wyslij_ponownie(zid):
    if wyslij_zapytanie(zid):
        flash("Wysłano zapytanie.", "ok")
    else:
        flash("Nie udało się wysłać – szczegóły w opisie i w zakładce Log.", "err")
    return redirect(url_for("zapytanie", zid=zid))


@app.route("/zapytanie/<int:zid>/usun", methods=["POST"])
def usun(zid):
    db().execute("DELETE FROM zapytania WHERE id=?", (zid,))
    db().commit()
    flash("Usunięto zapytanie z listy (pliki zostały w folderze danych).", "ok")
    return redirect(url_for("lista"))


@app.route("/pdf/<int:zid>")
def pdf(zid):
    z = db().execute("SELECT pdf FROM zapytania WHERE id=?", (zid,)).fetchone()
    if not z or not z["pdf"]:
        abort(404)
    return send_file(PDF_DIR / z["pdf"], mimetype="application/pdf",
                     as_attachment=bool(request.args.get("pobierz")), download_name=z["pdf"])


@app.route("/dokument/<int:did>")
def dokument(did):
    d = db().execute("SELECT plik FROM dokumenty WHERE id=?", (did,)).fetchone() or abort(404)
    return send_file(DOK_DIR / d["plik"], mimetype="application/xml", as_attachment=True,
                     download_name=d["plik"])


@app.route("/dokumenty")
def dokumenty():
    dok = db().execute("SELECT d.*, z.vin, z.upo FROM dokumenty d LEFT JOIN zapytania z "
                       "ON z.id=d.zapytanie_id ORDER BY d.id DESC LIMIT 300").fetchall()
    return render_template("dokumenty.html", dokumenty=dok)


@app.route("/ustawienia", methods=["GET", "POST"])
def ustawienia():
    if request.method == "POST":
        akcja = request.form.get("akcja", "zapisz")
        sr = request.form.get("srodowisko", "produkcja")
        sr = sr if sr in seap.ENDPOINTY else "produkcja"
        zapisz_ustawienie("srodowisko", sr)
        if akcja == "zapisz":
            zapisz_ustawienie(f"login_{sr}", request.form.get("login", "").strip())
            if request.form.get("haslo"):
                zapisz_ustawienie(f"skrot_{sr}", seap.skrot_hasla(request.form["haslo"]))
                if tryb_logowania(sr)["haslo"] != "skrot":
                    zapisz_ustawienie(f"haslo_{sr}", request.form["haslo"])
            zapisz_ustawienie(f"endpoint_{sr}", request.form.get("endpoint", "").strip())
            zapisz_ustawienie("target_systems", request.form.get("target_systems", "").strip())
            if request.form.get("ws_json", "").strip():
                try:
                    konf = json.loads(request.form["ws_json"])
                    assert set(konf["operacje"]) >= set(seap.OPERACJE)
                    obecna = konfiguracja_ws()
                    if {k: v for k, v in konf.items() if k not in ("zrodlo", "endpoint")} != \
                            {k: v for k, v in obecna.items() if k not in ("zrodlo", "endpoint")}:
                        konf["zrodlo"] = "ręcznie"
                        zapisz_ustawienie(f"ws_{sr}", json.dumps(konf, ensure_ascii=False))
                except (ValueError, KeyError, AssertionError, TypeError):
                    flash("Konfiguracja WS ma niepoprawny format – nie zapisano jej.", "err")
            db().commit()
            flash("Zapisano ustawienia.", "ok")
            if ustawienie(f"login_{sr}") and ustawienie(f"skrot_{sr}"):
                endpoint = ustawienie(f"endpoint_{sr}") or seap.ENDPOINTY[sr]
                if not ustawienie(f"ws_{sr}"):
                    if odczytaj_wsdl(sr, endpoint, wymus=True):
                        flash("Odczytano konfigurację SOAP z WSDL serwera PUESC.", "ok")
                    else:
                        flash(f"Nie udało się odczytać WSDL ({_PROBY_WSDL.get((sr, endpoint))}) – "
                              "użyto wartości domyślnych.", "warn")
                ok, msg = test_polaczenia()
                flash(msg, "ok" if ok else "err")
        elif akcja == "wsdl":
            endpoint = ustawienie(f"endpoint_{sr}") or seap.ENDPOINTY[sr]
            if odczytaj_wsdl(sr, endpoint, wymus=True):
                flash("Odczytano konfigurację z WSDL.", "ok")
            else:
                flash(f"Nie udało się odczytać WSDL: {_PROBY_WSDL.get((sr, endpoint))}", "err")
        elif akcja == "domyslne":
            zapisz_ustawienie(f"ws_{sr}", "")
            flash("Przywrócono domyślną konfigurację WS.", "ok")
        elif akcja == "test":
            db().commit()
            ok, msg = test_polaczenia()
            flash(msg, "ok" if ok else "err")
        db().commit()
        return redirect(url_for("ustawienia"))
    sr = srodowisko()
    konf = konfiguracja_ws()
    return render_template("ustawienia.html", login=ustawienie(f"login_{sr}"),
                           zrodlo_ws=konf.get("zrodlo", "domyślne"),
                           blad_wsdl=_PROBY_WSDL.get((sr, konf["endpoint"]), ""),
                           ma_haslo=bool(ustawienie(f"skrot_{sr}")),
                           endpoint=ustawienie(f"endpoint_{sr}"), domyslny_endpoint=seap.ENDPOINTY[sr],
                           target_systems=ustawienie("target_systems"),
                           ws_json=json.dumps(konf, ensure_ascii=False, indent=2))


@app.route("/diagnostyka", methods=["GET", "POST"])
def diagnostyka():
    sr = srodowisko()
    wynik, login = None, ustawienie(f"login_{sr}")
    if request.method == "POST":
        login = request.form.get("login", "").strip() or login
        haslo = request.form.get("haslo", "")
        if not login or not haslo:
            flash("Wpisz login i hasło PUESC – diagnostyka potrzebuje hasła, by sprawdzić warianty podpisu.", "err")
            return redirect(url_for("diagnostyka"))
        if haslo and seap.skrot_hasla(haslo) != ustawienie(f"skrot_{sr}") and ustawienie(f"skrot_{sr}"):
            flash("Uwaga: wpisane hasło różni się od zapisanego w Ustawieniach.", "warn")
        wynik = seap.diagnozuj(konfiguracja_ws(auto_wsdl=True), login, haslo, log_dir=LOG_DIR)
        if wynik["dzialajacy"]:
            t = wynik["dzialajacy"]
            zapisz_ustawienie(f"login_{sr}", login)
            zapisz_ustawienie(f"skrot_{sr}", seap.skrot_hasla(haslo))
            zapisz_ustawienie(f"tryb_{sr}", json.dumps(t))
            # hasło zapisujemy tylko, gdy wariant go wymaga (inaczej wystarczy skrót)
            zapisz_ustawienie(f"haslo_{sr}", haslo if t["haslo"] != "skrot" else "")
            zapisz_ustawienie(f"korekta_{sr}", str(wynik["przesuniecie_uzyte"]))
            db().commit()
            flash(f"Logowanie działa ({seap.opis_trybu(t)}) – zapisano ten wariant.", "ok")
    return render_template("diagnostyka.html", wynik=wynik, login=login, opis_trybu=seap.opis_trybu,
                           tryb=tryb_logowania(sr), teraz_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))


@app.route("/log")
def log():
    pliki = sorted(LOG_DIR.glob("*.txt"), reverse=True)[:100]
    wybrany = request.args.get("plik")
    tresc = ""
    if wybrany and (LOG_DIR / wybrany).is_file() and Path(wybrany).name == wybrany:
        tresc = (LOG_DIR / wybrany).read_text("utf-8", "replace")
    return render_template("log.html", pliki=[p.name for p in pliki], wybrany=wybrany, tresc=tresc)


@app.route("/eksport.csv")
def eksport():
    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["ID", "Utworzono", "Środowisko", "VIN", "UPO", "Status", "Nr potwierdzenia",
                "Data zapłaty", "Kwota akcyzy", "Marka i model", "Urząd", "Plik PDF", "Opis"])
    for z in db().execute("SELECT * FROM zapytania ORDER BY id"):
        w.writerow([z["id"], z["utworzono"], z["srodowisko"], z["vin"], z["upo"],
                    STATUSY.get(z["status"], (z["status"],))[0], z["doc_no"], z["data_zaplaty"],
                    (z["kwota_akcyzy"] or "").replace(".", ","), z["marka_model"], z["organ"], z["pdf"], z["opis"]])
    return Response("﻿" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=potwierdzenia_{date.today()}.csv"})


@app.route("/kopia")
def kopia():
    return send_file(DB_PATH, as_attachment=True, download_name=f"zefir2_{date.today().isoformat()}.sqlite")


init_db()

if __name__ == "__main__":
    import threading
    import webbrowser
    port = int(os.environ.get("PORT", 5010))
    if not os.environ.get("ZEFIR_NO_BROWSER"):
        threading.Timer(1.5, webbrowser.open, args=(f"http://127.0.0.1:{port}",)).start()
    app.run(host="127.0.0.1", port=port, debug=False)
