# Windows 10 IoT Core - Arhitektura, komponente i razvoj IoT aplikacija

**Windows 10 IoT** je familija operativnih sistema dizajniranih za embedded uređaje. **Windows 10 IoT Core** je jedan od ovih sistema i namenjen je manjim low-cost uređajima, jedan od primera je *Raspberry Pi*. Ovaj operativni sistem približava enterptise nivo performansi, sigurnost i povezanost na cloud IoT uređajima. Jedna od osnovnih ideja je pružanje mogućnosti izrade više odvojenih uređaja u ekosistemu i njihovu povezanost i sinhronizaciju preko cloud-a.

**Windows 10 IoT Core** je ujedno i sistem najmanjeg obima od ostalih iz ove familije. Ovo je verzija Windows-a 10 projektovana za pokretanje na ARM i x86/x64 uređajima. Postoje ograničenja u odnosu na ostale verzije. Na primer, dozvoljeno je pokretanje jedne aplikacije, za razliku od **Windows 10 IoT Enterprise** sistema koji je puna verzija Windows-a 10 prilagođena izradi aplikacija za  periferne uređaje.

Pregled ključnih razlika (ili ograničenja) ova dva sistema:

Mogućnosti | Windows 10 IoT Core | Windows 10 IoT Enterprise
--- | --- | ---
Korisničko iskustvo | Jedna UWP aplikacija u *foreground-u* sa podržanim *background* aplikacijama - `IoT Shell` | Multi-tasking i podrška pozadinskih aplikacija - potpuni `Windows Shell`
Headless podrška | Da | Da
Menadžment | MDM | MDM
Podržana arhitektura aplikacija | UWP | UWP, WinForms, etc.
Podržana arhitektura procesora | x86, x64 i ARM | x86 i x64

### Razlike u odnosu na Windows 10 Desktop

Može se reći da je **Windows 10 IoT Core** ograničen u odnosu na desktop verziju Windows-a 10. Uređaji boot-uju u takozvanu *Default aplikaciju* koja je interaktivna (poput UI Shell-a) i otvorenog koda pa se može koristiti kao osnova za razvijanje aplikacija.

**Dostupnost driver-a** je ograničena. Da bi neki uređaji mogli da se koriste na Windows 10 IoT Core sistemu poput desktop verziji istog, neophodno je build-ovati driver (na osnovu izvornog koda). Ovo je posebno prisutno na ARM arhitekturi.

**Registry-set** nije identičan i postoje segmenti koji se ne poklapaju ili nisu prisutni.

**Komande (PowerShell) i privilegije pristupa direktorijumima** su u nekim segmentima ograničene, iz ugla UWP aplikacija koje se razvijaju.

### IoT Shell

Svaki **IoT Core uređaj** se izvršava nad `IoT Shell-om`. Osnovno zaduženje je pokretanje aplikacija i može se izvršavati u dva moda - Headed i Headless. U Headed modu se izvršava na uređaju koji ima displej i jedna aplikacija se pokreće u fullscreen-u. U Headless modu se izvršavaju jedino pozadinske aplikacije.

**Foreground aplikacije** poseduju korisnički interfejs, jedna se pokreće prilikom boot-ovanja i korisnik može da bira koja će se još pokrenuti od svih registrovanih aplikacija. Ove aplikacije se izvršavaju u Headed modu. **Background aplikacije** nemaju UI i ne zahtevaju displej, često se izvršavaju sve vreme dok je uređaj uključen. Izvršavaju se u Headless modu i često se koriste za monitoring i slično.

Jedan od načina za **switching između aplikacija** je HID Injection. Postoji više hotkey-eva poput `Home`, `Previous app` ili `Next app`  koji se koriste za promenu aplikacija i navigaciju između njih.

## Arhitektura

## Komponente

## Podrška u razvoju aplikacija

## Demo aplikacija
