# Potwierdzenia zapłaty akcyzy za samochód – ZEFIR2 / PUESC

Lokalna aplikacja do pobierania potwierdzeń zapłaty akcyzy za samochód z systemu ZEFIR2
przez WebService PUESC: wysyła zapytania **PZAS** (po VIN albo po numerze UPO deklaracji),
odbiera odpowiedzi i zapisuje PDF-y potwierdzeń.

> Aplikacja łączy się domyślnie z **produkcyjnym** PUESC (`https://ws.puesc.gov.pl/seap_wsChannel/DocumentHandlingPort`).
> Struktura komunikatów PZAS pochodzi z oficjalnej specyfikacji ZEFIR2, a kanał z „SEAP PLUS –
> Specyfikacja Techniczna Publiczna” v5.50. Dokumentacja nie podaje przestrzeni nazw SOAP – aplikacja
> odczytuje je z WSDL serwera przy pierwszym połączeniu. Wymagań co do podpisu PZASReq i uprawnień
> do zapytań o cudze VIN-y dokumentacja też nie opisuje – patrz „Do sprawdzenia” na końcu.

## Uruchomienie – wersja przenośna dla Windows (bez instalacji)
1. Pobierz `Zefir2Akcyza-windows.zip` z najnowszego wydania w zakładce **Releases**
   (albo najnowszą wersję testową: zakładka **Actions** → ostatnie uruchomienie → *Artifacts*).
2. Rozpakuj i kliknij dwukrotnie `uruchom.bat`. Aplikacja otworzy się w przeglądarce (http://127.0.0.1:5010).
3. Dane są w folderze `dane/` obok `uruchom.bat`.

Paczkę buduje automatycznie GitHub Actions (`.github/workflows/paczka-windows.yml`)
przy każdej zmianie w gałęzi `main` – najpierw uruchamia testy offline, potem buduje paczkę
z wbudowanym Pythonem i publikuje ją jako nowe wydanie (v0.1.N) w Releases.

## Uruchomienie z kodu (dla programisty)
Wymaga Pythona 3.10+: `uruchom.bat` (Windows) lub `./uruchom.sh` (Linux/macOS).
Testy: `python -m unittest discover -s tests -v` (bez połączenia z PUESC – udawany serwer SOAP).

## Pierwsze uruchomienie
1. **Ustawienia** (domyślnie środowisko **Produkcja**) → login (e-mail konta PUESC) i hasło →
   **Zapisz i sprawdź połączenie**. Aplikacja:
   - zapisuje tylko `Base64(SHA-1(hasło))` potrzebne do WS-Security, nie samo hasło,
   - odczytuje z WSDL serwera właściwe przestrzenie nazw i akcje SOAP,
   - wywołuje `GetDocuments` za dzisiaj (nic nie wysyła, nie oznacza dokumentów jako pobranych).
2. Gdy pojawi się „Połączenie z PUESC (produkcja) działa” – można wysyłać zapytania.
3. Środowisko testowe (`te-ws.puesc.gov.pl`, osobne konto na test.puesc.gov.pl) można włączyć
   w Ustawieniach – login, hasło i konfiguracja są pamiętane osobno dla każdego środowiska.
   W nagłówku zawsze widać, które środowisko jest aktywne.

## Błąd „A security error was encountered when verifying the message”
PUESC odrzucił nagłówek logowania WS-Security. **Ustawienia → Diagnostyka logowania**: po wpisaniu
hasła aplikacja sprawdza (operacją GetDocuments za dziś, bez wysyłania czegokolwiek):
- różnicę zegara komputera i serwera PUESC (dopuszczalne ±5 minut) – przy dużej różnicy stosuje korektę,
- warianty podpisu: digest ze skrótu hasła (wzór z specyfikacji PUESC), digest z samego hasła (standard OASIS),
  z `wsu:Timestamp` i bez, hasło jawne `PasswordText` (w HTTPS).

Pierwszy działający wariant zostaje zapisany. Jeśli żaden nie działa – problem leży po stronie konta:
login musi być e-mailem konta na właściwym środowisku, a konto musi mieć własne hasło PUESC
(samo logowanie przez login.gov.pl nie wystarcza do WebService).

## Szybkie pobranie PDF (jak na PUESC)
Na stronie **Zapytania** wpisz VIN (albo kilka) i kliknij **Pobierz PDF**. Aplikacja wysyła zapytanie PZAS,
co 15 s sprawdza, czy ZEFIR2 odpowiedział, i od razu pobiera PDF – ten sam dokument, który daje PUESC
(„Dokument potwierdzający zapłatę akcyzy na terytorium kraju”, pole `doc` odpowiedzi PZASResp).
- Przy kilku VIN-ach – przycisk **Pobierz wszystkie PDF-y (ZIP)**.
- Jeśli PDF dla danego VIN już jest, aplikacja nie pyta PUESC ponownie (chyba że zaznaczysz „zapytaj ponownie”).
- **PDF-y (ZIP)** na liście zapytań – wszystkie zapisane potwierdzenia (z uwzględnieniem wyszukiwania).
- Nazwa pliku: `Potwierdzenie_zaplaty_akcyzy_<VIN>.pdf`.

## Praca
1. **Nowe zapytanie** – wklej VIN-y (po jednym w wierszu) albo podaj numer UPO deklaracji
   (opcjonalnie potwierdzenie zbiorcze + kwota dokumentu). Każde zapytanie jest walidowane z XSD przed wysłaniem.
2. **Zapytania** → *Sprawdź odpowiedzi* po kilku minutach (PUESC prosi, by nie odpytywać częściej niż co 5 minut).
3. Status **Potwierdzone** = przyszła odpowiedź PZASResp z PDF-em – przycisk *PDF* przy zapytaniu.
   **Odrzucone** = NPP (np. brak podpisu albo błąd schematu) – opis błędu jest przy zapytaniu.
4. *Eksport CSV* – lista zapytań z numerami potwierdzeń, datami i kwotami akcyzy (do Excela).

## Jak to działa
| Krok | Operacja SEAP | Treść |
|---|---|---|
| Wysłanie | `AcceptDocument` | `PZASReq` (base64 w `document/content`), w odpowiedzi `sysRef` |
| Odbiór dla zapytania | `GetDocuments(korelacjaSysref=sysRef, pobrany=0)` | UPP/NPP, UPO, `PZASResp` |
| Przegląd nowych | `GetDocuments(dataOd..dataDo ≤ 10 dni, pobrany=2)` | dokumenty bez korelacji – `PZASResp` przypisywany po VIN |

- Uwierzytelnienie: WS-Security `UsernameToken`/`PasswordDigest` wg wzoru PUESC
  `Base64(SHA-1(nonce + created + Base64(SHA-1(hasło))))`, `wsu:Created` w UTC, WS-Addressing z `MessageID`.
- `PZASResp/doc` (base64) to gotowy PDF potwierdzenia – zapisywany w `dane/potwierdzenia/`.
- Każda wymiana SOAP jest zapisywana w zakładce **Log** (`dane/log/`, bez hasła i nonce) –
  przydaje się przy zgłoszeniu do helpdesku PUESC.

## Pliki
- `app.py` – aplikacja (Flask), `seap.py` – klient WebService SEAP, `pzas.py` – komunikaty PZAS.
- `schematy/` – oficjalne XSD: `PZASReq.xsd` (v2_0), `PZASResp.xsd` (v4_0), `Types_Z2.xsd`, `Types_Z3.xsd`
  (ze „Specyfikacja XML ZEFIR2 08.09.2026”).
- `tests/` – testy offline z przykładową odpowiedzią PZASResp ze specyfikacji.

## Do sprawdzenia przy pierwszym zapytaniu
- czy SEAP przyjmuje niepodpisany PZASReq (jeśli przyjdzie NPP z informacją o podpisie – trzeba dodać podpis XAdES),
- czy odpowiedź PZASResp jest skorelowana z `sysRef` zapytania (jeśli nie – działa dopasowanie po VIN),
- czy konto może pytać o VIN-y z deklaracji złożonych przez inne podmioty.

Jeśli coś nie działa, szczegóły są w zakładce **Log** – zapis żądania i odpowiedzi SOAP bez hasła.
