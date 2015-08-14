#1. MPASS - Palvelun kuvaus

##1.1. Palvelun visio
MPASS-autentikointi ja kirjautumispalvelu on CSC:n tuottama ratkaisu perusopetuksen kevyeksi kertakirjautumisjärjestelmäksi. MPASS-järjestelmän teknisen toteutuksen dokumentointi löytyy githubista (osoite). MPASS-palvelun tarkoituksena on toimia digitaalisten edutech-tuotteiden yhdistävänä puitteena, joka mahdollistaa oppilaan kirjautumisen eri tuotteisiin yhdellä tunnuksella sekä oppilaan valittujen tietojen siirtymisen eri järjestelmien välillä. 
Oppilaiden ja opettajien näkökulmasta palvelu mahdollistaa tilanteen, jossa oppilas, opettajat ja heidän vanhempansa voivat hyödyntää olemassa olevia kirjautumistunnuksia (SoMe/Wilma/Helmi/yms. –tunnukset) kirjautuessaan eri palveluihin. Opetustilanteissa palvelu vähentää kirjautumiseen ja hävinneiden tai unohtuneiden tunnusten etsimiseen käytettävää aikaa. Käyttökokemuksen näkökulmasta palvelu helpottaa eri palveluiden tai sisältöjen hyödyntämisen yhtenäisemmäksi tekemistä ja mahdollistaa parhaimmillaan kokemuksen yhtenäisestä digitaalisten oppimistuotteiden käytöstä.
Uusia edutech-palveluita tuottaville palvelun tarjoajille MPASS-tarjoaa mahdollisuuden päästä helpommin oppilaitosten ja oppilaiden käytettäväksi. Integroimalla MPASS-palvelun osaksi omaa tuotettaan, varmistaa palvelun tarjoaja että perusopetuksen piiriin kuuluvilla oppilailla on jo oletusarvoisesti toimiva kirjautumistunnus palveluun jo ennen kuin tuote on valmistunut. Hankkeen myöhemmässä vaiheessa MPASS vähentää palvelun tarjoajien tarvetta ylläpitää asiakaskohtaisia oppilasrekistereitä tarjoamalla käyttöön keskitetyn oppilasID-rekisterin. 
MPASS-palvelu mahdollistaa myös edutech-sektorin ulkopuolisten toimijoiden saattaa omat digitaaliset palvelut osaksi perusopetukseen kuuluvien oppilaiden palveluvalikkoa. Näitä toimijoita voivat olla mm. vapaa-ajan harrastuksia tai palveluita tarjoavat toimijat mm. järjestösektorilla. 

#2. Projektin sisältö
##2.1. Ajankohta ja kesto 

Projekti toteutetaan 9/2015-12/2015 välisenä aikana. Kesto yhteensä 4 kuukautta.
##2.2. Lopputulokset

- **Toteutussuunnitelma**
Ensimmäisen vaiheen aikana CSC:n toteuttama kirjautumisjärjestelmä jalkautetaan perusopetukseen kuuluvien pilottioppilaitosten digitaalisiin oppimistuotteisiin. Pilotissa pyritään lisäksi helpottamaan kirjautumisen käyttöönottoa tuottamalla kirjautumisratkaisusta kehittäjätyökalupaketti tai muita käyttöönottoa helpottavia keinoja, jonka avulla erilaiset palvelun tarjoajat voivat sisällyttää MPASS-kirjautumisratkaisun omaan digitaaliseen oppimistuotteiseen. Projektin aikana testataan kirjautumisratkaisun ja sen käyttöönottoa tukevan kehittäjätyökalupaketin toimivuutta.
Kokeiluympäristöinä toimivat erilaiset peruskoulut sekä palveluntarjoajat, jotka ovat kiinnostuneet kehittämään omia digitaalisia oppimistuotteita. Lisäksi MPASS-kirjautumisjärjestelmä toteutetaan osaksi EduCloudAlliancen digitaalisten oppimateriaalien kauppapaikan pilottia syksyllä 2015.
Projektin ensimmäisen vaiheen aikana keskitytään lisäksi niihin ratkaisuihin, joissa toteutetaan kevyen tunnistautumisen ratkaisuja sekä etsitään pilottikohteita, joissa kirjautumisen tapa poikkeaisi normaalista käyttäjätunnus / salasana yhdistelmästä. 

- **Käyttäjätarinat**
Kerätään sähköisellä järjestelmällä avoimesti alkusyksystä 2015. Käyttäjätarinoita haetaan olemassa olevien verkostojen kautta, mukaan lukien Facebook:n opetukseen liittyvät yhteisöt sekä mm. Opetushallituksen Majakka-verkosto. Käyttäjätarinoiden kautta hahmotetaan käytännön kehittämistarpeita tekniselle toteutukselle sekä käyttöliittymälle.

- **Kirjautumisjärjestelmän tekninen ratkaisu ja dokumentaatio (CSC:ltä)**
MPASS-palvelu ja sitä koskeva dokumentaatio asetetaan Githubiin sen asennusta tukevine ohjeineen. Kaikki palveluun liittyvä materiaali julkaistaan avoimena lähdekoodina. 

- **Kilpailutus dokumentit** (Tarvittaessa)
- **Hankintapäätös** (Tarvittaessa)
Projektin lopussa MPASS – on käytössä pilottiin osallistuneiden oppilaitosten digitaalisissa oppimistuotteissa ja osassa näistä oppimistuotteista on toteutettu kirjautumistapa, joka perustuu muuhun kuin käyttäjätunnus / salasana –yhdistelmään. Sen lisäksi palveluntarjoajille ja oppilaitoksille tuotettu SDK on valmis.

##2.3. Projektin kuvaus ja kohde
Suomen koulutusjärjestelmään kuuluvissa perus- ja toisen asteen oppilaitoksissa on käytössä laaja kirjo erilaisia järjestelmiä ja ohjelmistoja, jotka vaativat käyttäjältään kirjautumista. Käytännössä on muodostunut tilanne, jossa yksittäinen käyttäjä joutuu ylläpitämään useita erilaisia tunnuksia ja salasanoja.  Tilanne aiheuttaa perus- ja toisen asteen oppilaitoksissa ajallista resurssihukkaa, joka on pois opetukseen käytettävästä ajasta. Ongelma koskettaa noin 550 000 oppilasta sekä 100 000 henkilökuntaan laskettavaa henkilöä, jotka ovat jakautuneet useisiin satoihin kuntiin ja niissä edelleen tuhansiin oppilaitoksiin. Tilanteen ratkaisu toisi merkittävää parannusta digitaalisten oppimistuotteiden käyttökokemukseen sekä parantaisi resurssitehokkuutta oppilaitoksissa, joissa hyödynnetään digitaalisia oppimisjärjestelmiä tai oppimismateriaaleja. Yliopistoilla ja ammattikorkeakouluilla tilanne on ratkaistu jo pidemmän aikaa HAKA-luottamusverkostolla ja identiteettihallintakäytännöllä, jolloin yksittäisellä opiskelijalla on käytössään yksi käyttäjätunnus ja salasana, joka on käytössä kaikissa eri järjestelmissä. Viranomaisten järjestelmissä vastaava ratkaisu on ollut Virtu-tunnistautumisjärjestelmä.
Koska perus- ja toisen asteen oppilaitosten opiskelijoista suurin osa on alaikäisiä, tulee tunnistautumisratkaisun hyödyntää kevyitä tunnistautumisratkaisuja nykyisten vahvojen tunnistautumiskäytäntöjen sijaan. Olemassa olevat vahvan tunnistautumisen käytännöt ovat toimivuudeltaan jäykkiä. Tämän lisäksi Vetuma-tunnistautuminen pohjautuu pitkälti verkkopankkitunnuksiin, joita ei myönnetä alle 15-vuotiailla ja vain osalla 15-17 –vuotiaista on niitä käytössä. Toisen haasteen tunnistautumisratkaisulle asettavat ne lapset, jotka ovat oppilaitoksissa mutta eivät ole vielä oppineet lukemaan. Näissä tapauksissa kirjautumis- ja tunnistautumisratkaisun tulisi olla sellainen, joka ei pohjaudu käyttäjätunnus ja salasana –yhdistelmään. Tulee lisäksi ottaa huomioon liikehdintä, jossa muutenkin pyritään kehittämään edistyneempiä tunnistautumisratkaisuja henkilökohtaisten digitaalisten palveluiden käyttöön. 

##2.4. Ratkottavat ongelmat ja tavoitteet

**Keskeiset ratkottavat ongelmat ovat:**
- IdP-lähteiden hallinta pilotin ensimmäisen vaiheen aikana. 
- Kirjoitustaidottomille suunnattujen kirjautumiskäytäntöjen kartoitus ja käyttöönoton kokeilu
- OID:n IdP-käyttöön liittyvien esteiden tai haasteiden kartoitus

**Projektin keskeisimmät tavoitteet ovat:**
- MPASS-kirjautumisratkaisun jalkauttaminen mahdollisimman laajalle
- MPASS-kirjautumisratkaisun helpon käyttöönoton ratkaisu
- Pilottikoulujen IdP-lähteiden hallinta

##2.5. Projektin omistaja.
Tuotepäällikkö:  (OKM)
Projektipäällikkö: nimetään myöhemmin, vastaa läpiviennistä.

##2.7. Toteutuksen osapuolet
- OKM/kopo
- Asiakasedustaja: EduCloud Alliance
- Asiakasedustaja: Linkki-keskus, Helsingin yliopisto
- Asiakasedustaja: koulu x
- Asiakasedustaja: Koulu y
- Toteuttava osapuoli: CSC

#3. Toteutus

##3.1. Läpiviennin yleiset periaatteet
    Miten kytkeytyy isoon kuvaan OKM ja valtion tasolla?
    - Lainmuutoksia vaativat asiat, Seuraavassa vaiheessa yhteys OID:n teknisellä tasolla
    Miten varmistetaan tiedonkulku muiden hankkeiden suuntaan?
    Yhteistyön kuvaaminen, miten siilot rikotaan?

##3.2. Aikataulu ja vaiheistus
Kehitysprojektin tämä vaihe toteutetaan 10/2015 - 12/2015. Keväällä 2016 vaihe 2.

##3.3. Vaiheet
Alla on kuvattu projektiin sisältyvien osaprojektien/tehtäväkokonaisuuksien päävaiheet ja niiden keskeiset tehtävät.

###3.3.1. MPASS Kirjautumisjärjestelmä 
Valmistumisaste 90%.

###3.3.2. Suunnitteluasiakirja
Palvelun kehitysprojektin suunnittelu (tämän dokumentin laatiminen). Suunnitelma perustuu digikopo -ryhmän hyväksymään palvelun kehityscanvakseen. Tämän suunnitelman mukaisen kehityksen aloittamisesta päättää Digipalvelutehtaan ohjausryhmä kehittämispäällikön esityksestä. 
    Vaihe valmistuu 14.8.2015 mennessä
Vaiheessa syntyvät tuotokset:
    Toteutussuunnitelma

###3.3.3. Pilottikumppanien hankinta
Palvelun testaamisessa mukana olevat oppilaitokset ja oppimistuotteiden tuottajat kerätään mukaan avoimella kutsulla keskeisten sosiaalisen median ympäristöjen sekä olemassa olevien muiden verkostojen välityksellä.  Mukana olevilta kumppaneilta kerätään tarpeita MPASS-kirjautumisen sekä sen mahdollistavan SDK:n toteuttamista varten. 
    Vaihe valmistuu 28.8.2015 mennessä
Vaiheessa syntyvät tuotokset:
Luettelo kehittämistarpeista
Luettelo mukana olevista tahoista
###3.3.4 Evaluointi ja jatkosta päättäminen
Lopputulos evaluoidaan yhdessä sidosryhmien (asiakasedustus, OKM edustus) kanssa 15.12.2015 mennessä. Evaluoinnin perusteella tuoteomistaja tekee päätöksen jatkotoimista. Mikäli kehittämistä päätetään jatkaa, tehdään seuraavan kehitysvaiheen suunnitteludokumentti 31.1.2016 mennessä valmiiksi.

#4. Projektin organisointi

##4.1. Projektin hallinnollinen organisointi

##4.2. Ohjausryhmä
Ohjausryhmä on OKM:n Digipalvelutehtaan ohjausryhmä, joka perustetaan syksyllä 2015.

##4.3. Roolit, vastuut ja velvollisuudet

##4.4. Viestintä ja tiedonvaihto.
    Kaikki käyttäjätarinat ja bugit Githubiin palvelun issue lokiin.
    Palvelusta kirjoitetaan OKM sisäiseen ja ulkoiseen digilehteen juttu syksyllä
    Viestintää ja dialogia sosiaalisen median kautta

##4.5. Tuotokset

#5. Työmääräarvio ja kustannusarvio. (edited)

#6. Muuta

