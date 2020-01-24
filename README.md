# Windows 10 IoT Core - Arhitektura, komponente i razvoj IoT aplikacija

**Windows 10 IoT** je familija operativnih sistema dizajniranih za embedded uređaje. **Windows 10 IoT Core** je jedan od ovih sistema i namenjen je manjim low-cost uređajima, jedan od primera je *Raspberry Pi*. Ovaj operativni sistem približava enterptise nivo performansi, sigurnost i povezanost na cloud IoT uređajima. Jedna od osnovnih ideja je pružanje mogućnosti izrade više odvojenih uređaja u ekosistemu i njihovu povezanost i sinhronizaciju preko cloud-a.

**Windows 10 IoT Core** je ujedno i sistem najmanjeg obima od ostalih iz ove familije. Na primer, dozvoljeno je pokretanje jedne aplikacije, za razliku od **Windows 10 IoT Enterprise** sistema koji je puna verzija Windows-a 10 prilagođena izradi aplikacija za menje periferne uređaje.

Evo pregleda ključnih razlika (ili ograničenja) ova dva sistema:

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

Svaki **IoT Core uređaj** se izvršava nad `IoT Shell-om`.
  
## Arhitektura

## Komponente

## Podrška u razvoju aplikacija

## Demo aplikacija
