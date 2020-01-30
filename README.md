# Windows 10 IoT Core - Arhitektura, komponente i razvoj IoT aplikacija

**Windows 10 IoT** je familija operativnih sistema dizajniranih za embedded uređaje. **Windows 10 IoT Core** je jedan od ovih sistema i namenjen je manjim low-cost uređajima, jedan od primera je *Raspberry Pi*. Ovaj operativni sistem približava enterptise nivo performansi, sigurnost i povezanost na cloud IoT uređajima. Jedna od osnovnih ideja je pružanje mogućnosti izrade više odvojenih uređaja u ekosistemu i njihovu povezanost i sinhronizaciju preko cloud-a, pre svega sa Microsoft-ovom Azure platformom.

**Windows 10 IoT Core** je ujedno i sistem najmanjeg obima od ostalih iz ove familije. Ovo je verzija Windows-a 10 projektovana za pokretanje na ARM i x86/x64 uređajima. Postoje ograničenja u odnosu na ostale verzije. Na primer, dozvoljeno je pokretanje jedne aplikacije, za razliku od **Windows 10 IoT Enterprise** sistema koji je puna verzija Windows-a 10 prilagođena izradi aplikacija za  periferne uređaje.

Pregled ključnih razlika (ili ograničenja) ova dva sistema:

Mogućnosti | Windows 10 IoT Core | Windows 10 IoT Enterprise
--- | --- | ---
Korisničko iskustvo | Jedna UWP aplikacija u *foreground-u* sa podržanim *background* aplikacijama - `IoT Shell` | Multi-tasking i podrška pozadinskih aplikacija - potpuni `Windows Shell`
Headless podrška | Da | Da
Menadžment | MDM | MDM
Podržana arhitektura aplikacija | UWP | UWP, WinForms, etc.
Podržana arhitektura procesora | x86, x64 i ARM | x86 i x64

**Napomena: Demo aplikacija je razvijana i testirana u Microsoft-ovom okruženju i korišćeni su lokalni simualtori (gde se sistem izvršava u `Embedded modu`). Testbed okruženje Fit IoT-Lab nije korišćeno jer ne podržava Windows IoT Core.**

https://www.iot-lab.info/operating-systems/

### Razlike u odnosu na Windows 10 Desktop

Može se reći da je **Windows 10 IoT Core** ograničen u odnosu na desktop verziju Windows-a 10. Uređaji boot-uju u takozvanu *Default aplikaciju* koja je interaktivna (poput UI Shell-a) i otvorenog koda pa se može koristiti kao osnova za razvijanje aplikacija.

**Dostupnost driver-a** je ograničena. Da bi neki uređaji mogli da se koriste na Windows 10 IoT Core sistemu poput desktop verziji istog, neophodno je build-ovati driver (na osnovu izvornog koda). Ovo je posebno prisutno na ARM arhitekturi.

**Registry-set** nije identičan i postoje segmenti koji se ne poklapaju ili nisu prisutni.

**Komande (PowerShell) i privilegije pristupa direktorijumima** su u nekim segmentima ograničene, iz ugla UWP aplikacija koje se razvijaju.

### IoT Shell

Svaki **IoT Core uređaj** se izvršava nad `IoT Shell-om`. Osnovno zaduženje je pokretanje aplikacija i može se izvršavati u dva moda - Headed i Headless. U Headed modu se izvršava na uređaju koji ima displej i jedna aplikacija se pokreće u fullscreen-u. U Headless modu se izvršavaju jedino pozadinske aplikacije.

**Foreground aplikacije** poseduju korisnički interfejs, jedna se pokreće prilikom boot-ovanja i korisnik može da bira koja će se još pokrenuti od svih registrovanih aplikacija. Ove aplikacije se izvršavaju u Headed modu. **Background aplikacije** nemaju UI i ne zahtevaju displej, često se izvršavaju sve vreme dok je uređaj uključen. Izvršavaju se u Headless modu i često se koriste za monitoring i slično.

Jedan od načina za **switching između aplikacija** je HID Injection. Postoji više hotkey-eva poput `Home`, `Previous app` ili `Next app`  koji se koriste za promenu aplikacija i navigaciju između njih.

## Arhitektura i komponente

Kako IoT uređaji postaju važniji tako je i veća potreba za njihovim upravljenjem i sigurnošću. IoT se ne ograničava samo na uređaje već podrazumeva i ekosistem, odnosno servise na koje su povezani. Iz ovih razloga su važni operativni sistemi razvijeni sa IoT uređajima na umu - jedan od ovih sistema (familija sistema, tačnije) je **Windows 10 IoT**.

### Internet of Things - Osnovna arhitektura sistema

IoT arhitektura je sistem brojnih elemenata poput senzora, aktuatora, protokola, cloud servisa i drugih. Zbog ove kompleksnosti, predložena su **četiri faze ove arhitekture**. Arhitektura mora da podrži osovne zahteve ovih sistema - odnosno dostupnost, održivost i skalabilnost. Raznolikost uređaja u ovakvim sistemima je nametnula potrebu za jasno definisanom arhitekturom.

U osnovi, postoje tri sloja:
* Klijentska strana (IoT Device Layer)
* Operatori na serverskoj strani (IoT Getaway Layer)
* Povezivanje klijenata i operatora (IoT Platform Layer)


![alt text][architecture-iot]

[architecture-iot]: meta/architecture-iot.png

Faze, koje potkrepljuju arhitekturu su redom:
* Senzori i aktuatori
* Internet gateway-i i sistemi prikupljanja podataka
* Edge IT
* Centri za skladištenje podataka i cloud

#### Prva faza. Umreženi uređaji (wireless senzori i aktuatori)

Senzori su izvor stvarnih podataka i mogu biti embeddovani u uređajima ili odvojeni kao posebni objekti. Primer senzora su merači pritiska ili pak temperature. Osnovni zadatak senzora je da prikupljaju stvarne informacije i pretvaraju ih u podatke za dalju analizu. Zbog ovoga su u prvoj fazi, uslove treba transformisati u podatke koji mogu da se obrađuju. Aktuatori, sa druge strane, mogu da menjaju fizičke uslove poput gašenja svetla ili promene temperature. Zadatak aktuatora je da transformišu podatke u akcije. Faza osluškivanja (sensing) i aktuacije (actuating) pokriva sve što je potrebno u fizičkom svetu kako bi se dobili podaci za dalje faze.

Ono što je važno pored dvosmerne komunikacije sa ostalim slojevima (cloud-om, na kraju) jeste i interkomunkacija između uređaja u vidu razmene podataka koje oni poseduju. S obzirom da je komunikacija od posebne važnosti postoje posebni low-power protokoli za razmenu informacija koji to omogućuju o malom trošku energije.

#### Druga faza. Sistemi za agregaciju podataka sa senzora i analogno-digitalna konverzija

Data acquisition sistemi (DAS) se povezuju na mrežu senzora i agregiraju njen izlaz u vidu pred-procesiranja sirovih podataka. Gateway sistemi rade na nivou LAN ili bežičnih mreža i doprinose tako što prave bundle-ove podataka za dalje nivoe. Ideja je kompresovati obimne količine podataka koji se dobijaju sa senzora na skup podataka koji je lakše obradiv u sledećoj fazi. Ovaj sloj spaja najniži sloj fizičkih uređaja i viši sloj obrade podataka. Kako se nalazi između OT i IT sistema, gateway omogućava komunikaciju između senzora i ostatka sistema konvertujući pročitane podatke u oblik razumljiv višim slojevima. Takođe, filterovanjem prikupljenih podataka se dobija manji obim istih i smanjuje opterećenje cloud-a.

Još jedan zadatak ovog sloja je sigurnost u vidu enkripcije podataka koji se razmenjuju između slojeva, tako da ne može doći do curenja podataka iz IoT sistema.

#### Treća faza. Edge IT analytics sistemi

Ovo je faza kada se podaci iz fizičkog sveta prenose u IT svet. Posebno, IT Edge sistemi vrše analitike i pred-procesiranje pristuglih podataka. Svo pred-procesiranje pre ulaska u centre podataka se dešava ovde. Mogu se koristiti različite tehnike, poput mašinskog učenja i sličnih.

Ovaj sloj ne mora da bude deo svake IoT arhitekture i donosi poboljšanje u large-scale sistemima. Kako u IoT cloud sistemima postoji ograničenje u brzini transfera podataka, Edge sistemi mogu da ponude brže vreme obrade i kraća vremena odziva. Kako infrastruktura ovog sloja može da bude fizički bliža uređajima, lakše je i brže pristupiti podacima. U ovom slučaju, jedino najveći obim podataka se prosleđuje na cloud za dalju obradu.

#### Četvrta faza. Analiza, upravljanje i skladištenje podataka

Poslednja faza se dešava u centru podataka ili cloud-u. Ovde dolazi do detaljnijih ili *in-depth* analiza podataka uz revizije. Podaci se skladište u širokom i pouzdanom ekosistemu. Harvder cloud-a koji je na raspolaganju nudi mogučnost obrade velikih količina podataka, znatno većih od Edge sistema. Ovde su na raspolaganju endžini za analizu podataka, kao i mehanizmi mašinskog učenja. Na kraju, uređeni i procesirani podaci se dovode u fizičko okruženje.

Ako se cloud dopuni aplikativnim pregledom, mogu se ponuditi opcije prezentacije i pregleda podataka ili pak *business intelligence*. Ovakvi sistemi pružaju interakciju sa podacima, pregled izveštaja, donošenje odluka i akcija na osnovu podataka i slično - sve ovo je u realnom vremenu.

### Image sistema

Image-i ovog sistema su u Fast Flash Update (FFU) formatu. Detalji ovog formata mogu se pogledati [ovde](https://docs.microsoft.com/en-us/windows-hardware/manufacture/mobile/ffu-image-format?redirectedfrom=MSDN). Windows 10 IoT Core koristi V2 ovog formata.

### Paritcije i boot-ovanje

Image sistema poseduje četiri particije:

Particija | Filesystem | Putanja | Sadržaj
--- | --- | --- | ---
EFI System Partition | FAT | C:\EFIESP\ | Boot konfiguracija, UEFI aplikacije
Crash dump partition | FAT32 | D:\ | Dump podaci
Main OS | NTFS | C:\ | OPerativni sistem, registar, OEM aplikacije
Data partition | NTFS | U:\ | **Korisničke aplikacije i podaci**

EFI sistemska particija sadrži Windows Boot Manager i Boot konfiguracionu bazu podataka (BCD). Informacije od crash-ovima se smeštaju na drugoj particiji u tabeli. Operativni sistem i njegove komponente su na trećoj particiji. Poslednja, Data particija, sadrži sve instalirane korisničke aplikacije, podatke tih aplikacija i korisničke podatke.

Proces boot-ovanja se sastoji od više koraka:
1) Pokretanje uređaja i pokretanje SoC firmware bootloader-a
2) Ovaj bootloader pokreće UEFI okruženje sa `C:.\EFIESP\EFI\Microsoft\boot\bootmgfw.efi`
3) UEFI okruženje pokreće Boot manager sa `C:\Windows\System32\Boot\winload.efi`
4) Boot manager pokreće Windows boot loader i na kraju sam operativni sistem

### Aplikacije

Windows 10 IoT Core podržava više tipova aplikacija. Pre sve, **Universal Windows Platform (UWP) aplikacije**. UWP je deljena platforma više verzija Windows operativnog sistema - omogućava pisanje aplikacija koje se mogu pokretati na velikom broju raznolikih uređaja koje programer izabere da podrži. Kao što je prethodno pomenuto, na Windows 10 IoT Core sistemu može da se izvršava jedna ovakva aplikacija jednovremeno - pritom se misli na *foregraound aplikacije*. Podrazumevano postoji *default aplikacija* koja zauzima to mesto.

*Background aplikacije* se izvršavaju u pozadini i ne poseduju korisnički interfejs. Pokreću se nakon podizanja sistema i ne prekidaju se, sve dok ne dođe do greške ili pada. Postoji i ograničena podrška za pisanje non-UWP aplikacija u jeziku C++ ali moraju biti konzolne. Pritom nema mogućnosti korišćenja 	Win32	GUI	API-a.

Kao što je prethodno pomenuto, uređaju mogu raditi u dva moda - **Headed i Headless**. Headless mod ne zahteva interakciju sa korisnikom jer nema displeja. U Headed modu se izvršava jedna aplikacija u punom ekranu i interaktivna je. Svaki uređaj se može konfigurisati za izvršavanje u željenom modu.

#### IoT Extension SDK API Contracts

**Windows SDK uključuje Exctension SDK-ove** koji dozvoljavaju pozivanje specijalizovanih API-a u slučaju izvršavanja na određenim uređajima. Nakon odlučivanja koja **familija uređaja** će biti targetovana (podržana) treba referencirati Extension SDK koji implementira API tih uređaja. 

### Sigurnost

#### ASLR, DEP, i Control Flow Guard

Ovo su primeri otklanjanja ili ublažavanja poznatih kritičnih tačaka, odosno *exploit-a*. Svaka izvršna datoteka je kompajlirana sa ASLR-om i DEP-om. Control Flow Guard je takođe uključen za instalirane biblioteke.

> Address Space Layout Randomisation (ASLR) is a technology used to help prevent shellcode from being successful. It does this by randomly offsetting the location of modules and certain in-memory structures. Data Execution Prevention (DEP) prevents certain memory sectors, e.g. the stack, from being executed. When combined it becomes exceedingly difficult to exploit vulnerabilities in applications using shellcode or return-oriented programming (ROP) techniques.

> Control Flow Guard (CFG) is a highly-optimized platform security feature that was created to combat memory corruption vulnerabilities. By placing tight restrictions on where an application can execute code from, it makes it much harder for exploits to execute arbitrary code through vulnerabilities such as buffer overflows.

#### Trusted Platform Module (TPM)

TPM je kripto-procesor koji omogućava kriptografske operacije poput kreiranja ključeva za šifriranje i njihovog skladištenja. Ovo je poseban mikrokontroler dizajniran da osigura hardver preko integrisanog šifriranja. Maliciozni softver nije u mogućnosti da se meša u sigurnosne operacije obavljane od strane TPM-a.

#### Secure Boot i Bitlocker

Secure Boot ne dozvoljava mešanje ne-potpisanih izvršnih programa prilikom pokretanja sistema. Osmišljen je da zaštiti sistem od *bootkita, rootkita* i sličnog malvera niskog nivoa. Bitlocker omogućava enkripciju korisničkih i sistemskih datoteka. Obe komponente zahtevaju TPM modul kako bi mogle se koriste.

#### Windows Update

Veoma zastupljen problem IoT uređaja je promena verzija firmware-a. Proizvodjači retko dostavljaju automatska unapređenja i ovo se radi ručno. Sam proces instalacije nove verzije fimrware-a je komplikovan i podrazumeva više koraka. Windows update rešava ovaj problem nudeći automatsko ažuriranje ovog softvera niskog nivoa.

## Podrška u razvoju aplikacija

### Azure IoT Hub

**Azure IoT Hub** je servis hostovan na cloud-u koji se koristi kao centralizovani hub poruka za komunikaciju između IoT aplikacije i uređaja kojim ona upravlja. Ima smisla upotrebiti ga zbog sigurnih i stabilnih **dvosmernih komunikacija** između velikog broja uređaja i backend-a na koji se svi uređaji oslanjaju i sa kojim se pritom sinhronizuju. **IoT Hub Monitoring** se može koristiti za praćenje statusa sistema i vođenje evidencije o kritičnim događajima. IoT Hub je skalabilan do više miliona simultano povezanih uređaja. 

**Sigurni komunikacioni kanali** omogućavaju:
* Autentifikaciju na nivou svakog uređaja prilikom ostvarivanja veze sa cloud-om
* Kontrola pristupa uređaju, kao i kontrola otvorenih konekcija
* Više načina autentifikacije
  * SAS token-based
  * Individual X.509 certificate
  * X.509 CA authentication

Integracija je moguća sa drugim Azure servisima poput *Azure Event Grid-a* ili *Azure Machine Learning-a*. Takođe, konfiguracija uređaja (u smislu promene stanja, pre svega) na pojedinačnom nivou ili na grupnom. Konfiguracija može biti vođena događajima. Moguće je podešavanje odgovora u vidu slanja poruka koje se rutiraju do neke backend tačke u određenim situacijama.

Povezivanje uređaja *Azure IoT Device SDK* bibliotekama omogućava razvijanje aplikacija nad uređajima koji su u Hub-u. Podržano je više platformi poput Windows ili Linux operativnih sistema, kao i više različitih programskih jezika. Mogu se koristiti različiti protokoli za komunikaciju sa Hub-om kao što su HTTPS ili pak WebSocket.

#### Azure IoT Edge

**Azure IoT Edge** je servis koji se može izvršavati nad **Azure IoT Hub-om** embedded uređaja. Koristi se za deployment i rasoređivanje posla nad Hub-om više uređaja. Neki od primera su veštačka inteligencija ili pak biznis logika koji se izvršavaju na uređajima u vidu kontejnera. Ovakvi poslovi se guraju na "edge" sistema gde se izvršavaju i imaju jasnu svrhu. Podaci ne moraju da se procesiraju u cloud-u već odmah na uređaju oslanjajući se na njihov hardver što daje visok nivo real-time performansi.

### Raspberry Pi

Najosnovnije povezivanje Raspberry Pi uređaja na Azure Hub se svodi na njegovu registraciju i slanje podataka sa senzora na cloud. Potrebno je pokrenuti uređaj i razviti minimalnu aplikaciju koja će slati informacije sa senzora.

Neke od neophodnih stvari:
* Raspberry Pi 2 ili 3 ploča, napajanje za ploču
* microSD kartica na koju će se dodati Operativni sistem
* BME280 senzor temperature, pritiska ili vlažnosti vazduha

Uređaj je potrebno registrovati na prethodno napravljen Azure Hub. Celokupna procedura je objašnjena [na stranici znanične dokumentacije](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-raspberry-pi-kit-node-get-started).

#### Raspberry Pi simulator

Moguće je napraviti simulaciju Raspberry Pi uređaja i povezati je na IoT Hub. Senzori mogu da budu simulirani i podaci sa uređaja se mogu iskoristiti za prototip aplikaciju. Simulator je dostupan [ovde](https://azure-samples.github.io/raspberry-pi-web-simulator/#GetStarted).

Podrazumevano je na ploču povezan **BME280 senzor** i LED dioda. Dozvoljeno je menjati kod aplikacije koja se izvršava.

![alt text][raspberry-simulator]

[raspberry-simulator]: meta/raspberry-simulator.png

Ovako simulirani uređaj sa predefinisanim izvršnim kodom se može registrovari na Azure IoT Hub zbog daljeg testiranja.

#### Instalacija Windows IoT-a na uređaju

Podešavanje uređaja i instalacija *image-a* Windows 10 IoT Core vrši se kroz softver **IoT Dashboard**.

![alt text][iot-dashboard]

[iot-dashboard]: meta/iot-dashboard.jpg

Osnovna podešavanja uređaja se setuju iz softvera, ovo podrazumeva i mrežu na koju će se povezati Raspberry Pi uređaj. Treba precizirati drajv na kome se nalazi SD-kartica koja će se flešovati sistemom.

![alt text][iot-dashboard-installation]

[iot-dashboard-installation]: meta/iot-dashboard-installation.jpg

Nakon toga, image sistema se instalira na SD-kartici i može se preći na uređaj.

1) Prvo treba povezati micro USB kablom napajanje
2) Da bi uređaj bio u **headed** modu treba povezati HDMI kablom monitor
3) Flešovanu SD-karticu sa Windows sistemom treba staviti u slot uređaja
4) Pokrenuti uređaj

![alt text][iot-raspberry-pi]

[iot-raspberry-pi]: meta/iot-raspberry-pi.jpg

Nakon podizanja sistema dolazi se do početnog ekrana, kao što je već pomenuto na njemu se može izvršavati jedna aplikacija. Odavde je moguće raditi deployment i debagiranje aplikacija direktno iz  **Visual studio okruženja**, s obzirom da je poznata adresa uređaja.

### Visual studio kao razvojno okruženje

Kako Windows 10 IoT Core podržava UWP aplikacije, za razvijanje je najpogodnije koristiti **Microsoft Visual studio** kao razvojno okruženje. Neophodno je uključiti **Universal Windows Platform development** pack.

![alt text][ide-visual-studio]

[ide-visual-studio]: meta/ide-visual-studio.png

Moguće je razvijati **headed i headless aplikacije**, gde će headed varijante imati korisnički interfejs definisan `.xaml` datotekama. Pozadinske aplikacije ne poseduju korisnički interfejs i podržane su na svim uređajima.

Uokviru okruženja je moguće build-ovati aplikacije za arhitekture:
* `ARM`
* `x86/x64`

Proces debagiranja se može raditi **lokalno na mašini u simulatoru** gde se aplikacija izvršava u `sandbox-u` lokalnog operativnog sistema kao i svaka druga UWP aplikacija. Jedina je razlika u tome što se u sandboxu sistem nalazi u `Embedded mod-u`. Pristup je moguć svim senzorima i uređajima koji su na mašini, poput web-kamere. Simulatori su pogodni za rano testiranje prototipa.

Sa druge strane, ukoliko je uređaj povezan, može se vršiti deployment aplikacija direktno na uređaj (npr. Raspberry Pi). Tada se mogu očitavati svi senzori i prisupati aktuatorima stvarnog uređaja.

## Demo aplikacija

Demo aplikacija je predviđena za Raspberry Pi uređaj. Aplikacija je predviđena za **headed mod** pa je potrebno priključiti displej na uređaj.

Demo aplikacija ima za zadatak da posmatra **ulaz sa web-kamere** koja je priključena na uređaj (preko usb-a) i **signalizira kada je detektovano lice**. Signalizira se na displeju i aktuacijom diode koja je je prikačena na jednom od pinova uređaja.

**Napomena: Zbog neraspoloživosti Raspberry Pi uređaja nije korišćen senzor za prikupljanje informacija, već web-kamera. Uređaj je testiran jedino u simulatoru uokviru Windows sistema, gde se pritom sistem izvršava u `Embedded mod-u`. Iz ovog razloga je jako teško simulirati senzore jer je potrebno ručno pisati unsigned drajvere koji će simulirati fiktivne uređaje.**

### Povezivanje hardvera

Od opreme je potrebno:
* HDMI i USB kablovi
* Displej
* Web-kamera
* LED dioda, otpornik i jumper žica

Web-kamera se povezuje na jedan od dostupnih USB portova uređaja. Displej se povezuje na HDMI port i neophodan je s obzirom da je aplikacija predviđena za izvršavanje u **headed modu**. LED dioda se treba povezati na jedan od GPIO portova.

![alt text][raspberry-pi-led]

[raspberry-pi-led]: meta/raspberry-pi-led.png

### Funkcije, testiranje i deployment

Kako se izvršava na Raspberry Pi uređaju, treba ga pre svega povezati i izabrati `ARM` kao arhitekturu za build-ovanje. Uređaj se bira kao `Remote Device` i nakon build-ovanja se može na njemu pokrenuti aplikacija.

Kada se koristi lokalno testiranje, aplikacija se izvršava na Windows mašini u simulatoru (embedded mod). Na slici ispod se može videti proces pokretanja i debagiranja aplikacije iz simulatora.

![alt text][raspberry-pi-screen]

[raspberry-pi-screen]: meta/raspberry-pi-screen.png

Iz interfejsa se pokreće snimanje sa web-kamere preko dugmeta `Start recording video`. Video snimak je sačuvan na internoj memoriji. Dok je snimanje aktivno, uz pomoć API-ja za detekciju lica se vodi računa da li je lice prisutno. Čim nečije lice postane prisutno, naznačava se na ekranu i na period od 2000ms se aktuira LED dioda. Za vreme snimanja se prikazuje preview stream uokviru interfejsa.

### Implementacioni detalji

Prilikom pokretanja aplikacije se inicijalizuju uređaji za snimanje videa i portovi preko API-a koji nudi `Windows.Devices`. Metoda `EnumerateCameras` pronalazi uređaje koji su u mogućnosti snimanja video sadržaja. Sa druge strane, metoda `EnumerateHardware` ostvaruje vezu sa GPIO kontrolerom i konkretnim pinom koji je označen konstantom **DEVICE_PIN_ID**. Na odgovarajućem broju pina treba da se nalazi LED dioda kojom će se upravljati i na početku će se setovati na niski naponski nivo.

```c#
using Windows.Devices.Enumeration;
using Windows.Devices.Gpio;

...

private async void EnumerateCameras()
{
    var devices = await Windows.Devices.Enumeration.DeviceInformation.FindAllAsync(Windows.Devices.Enumeration.DeviceClass.VideoCapture);
    deviceList = new List<Windows.Devices.Enumeration.DeviceInformation>();

    if (devices.Count > 0)
    {
        for (var i = 0; i < devices.Count; i++)
        {
            deviceList.Add(devices[i]);
        }
        InitCaptureSettings();
        InitMediaCapture();
    }
}

private void EnumerateHardware()
{
    pinsList = new List<GpioPin>();
    var gpio = GpioController.GetDefault();

    if (gpio == null)
    {
        Debug.WriteLine("GPIO controller not found.");
        return;
    }

    pinsList.Add(gpio.OpenPin(DEVICE_PIN_ID));

    foreach (var pin in pinsList)
    {
        pin.Write(GpioPinValue.Low);
        pin.SetDriveMode(GpioPinDriveMode.Output);
    }
}
```

Pokretanje procesa snimanja aktivira dostpunu web-kameru, inicira snimanje sadržaja u internu memoriju, priprema `mediaCapture` za snimanje i dodaje listener za detekciju lica sa ulaza kamere.

```c#
private async Task StartMediaCaptureSession()
{
    await StopMediaCaptureSession();

    var storageFile = await Windows.Storage.KnownFolders.VideosLibrary.CreateFileAsync("_video.wmv", Windows.Storage.CreationCollisionOption.GenerateUniqueName);
    fileName = storageFile.Name;

    await mediaCapture.StartRecordToStorageFileAsync(profile, storageFile);
    await mediaCapture.StartPreviewAsync();
    isRecording = true;
}
```

Ukoliko je lice detektovano, potrebno je to naznačiti na ekranu (uokviru aplikacije) i aktuacijom LED diode. Aktuacija se svodi na dovođenje visokog naponskog nivoa preko GPIO kontrolera u trajanju od dve sekunde.

```c#
private void ActuateHardware()
{
    try
    {
        var ledDiode = pinsList[0];
        ledDiode.Write(GpioPinValue.High);

        Task.Delay(2 * 1000).Wait();

        foreach (var pin in pinsList)
        {
            pin.Write(GpioPinValue.Low);
        }
    }
    catch (Exception deviceError)
    {
        Debug.WriteLine(deviceError.ToString());
    }
}
```
