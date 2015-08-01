#1. MPASS - Palvelun kuvaus

##1.1. Palvelun visio
Tarkoituksena on luoda puitteet perusopetuksessa käytettävien digitaalisten oppimismateriaalien ja –ympäristöjen tunnistautumis- ja kirjautumiskäytännöille. Hankkeen tulokset mahdollistavat tilanteen, jossa perusopetuksessa oleva koululainen voi tietokoneelle kirjautumisen jälkeen käyttää yhdellä tunnuksella erilaisia digitaalisia oppimistuotteita. 
Käytännössä koululainen voisi kirjautua olemassa olevilla tunnuksilla (esim. Wilma-tunnus) sellaisiin digitaalisiin oppimateriaalituotteisiin, joita ei ole vielä käyttänyt. Ratkaisun hyöty on kaksi suuntainen. Oppilaalle ja oppilaitoksille se tarkoittaa helpompaa ja nopeampaa tapaa ottaa käyttöön uudenlaisia materiaaleja tai ympäristöjä. Näiden materiaalien tai ympäristöjen tuottajille ratkaisu puolestaan mahdollistaa valmiin käyttäjäryhmän, joilla on oletuksena valmiiksi tunnukset uusiinkin tuotteisiin.
Tunnistautumis- ja kirjautumisratkaisu mahdollistaa lisäksi muiden toimijoiden toteuttaa palveluihin kirjautuminen siten että se on yhteensopiva heti julkaisun jälkeen. Muita toimijoita voivat olla esimerkiksi muut peruskoululaisille palveluita tarjoavat viranomaiset tai kaupalliset toimijat. 

#2. Projektin sisältö

##2.1. Ajankohta ja kesto
Projekti toteutetaan 9/2015-12/2015 välisenä aikana. Kesto yhteensä 4 kuukautta.

##2.2. Lopputulokset
*Toteutussuunnitelma*
Projektin aikana CSC:n toteuttamasta kirjautumisratkaisusta tuotetaan kehittäjätyökalupaketti, jonka avulla erilaiset palvelun tarjoajat voivat sisällyttää MPASS-kirjautumisratkaisun omaan digitaaliseen oppimistuotteiseen. Oppilaitosten osalta MPASS-voidaan ottaa käyttöön niiden palveluiden osalta, jotka mahdollistavat kirjautumisen implementoinnin. 
Projektin aikana testataan kirjautumisratkaisun ja sen käyttöön ottoa tukevan kehittäjätyökalupaketin toimivuutta. Kokeiluympäristöinä toimivat erilaiset peruskoulut ja palveluntarjoajat, jotka ovat kiinnostuneet kehittämään omia digitaalisia oppimistuotteita. Lisäksi MPASS-kirjautumisjärjestelmä toteutetaan osaksi EduCloudAlliancen digitaalisten oppimateriaalien kauppapaikan pilottia syksyllä 2015.
Projektin ensimmäisen vaiheen aikana keskitytään lisäksi niihin ratkaisuihin, joissa toteutetaan kevyen tunnistautumisen ratkaisuja sekä etsitään pilottikohteita, joissa kirjautumisen tapa poikkeaisi normaalista käyttäjätunnus / salasana yhdistelmästä. 
*Kirjautumisjärjestelmän tekninen ratkaisu ja SDK (CSC:ltä)*
*Kilpailutus dokumentit* (Tarvittaessa)
*Hankintapäätös* (Tarvittaessa)
   
Kaikki tuotokset Githubissa, käytetään lähtökohtaisesti avointa lähdekoodia
Projektin lopussa MPASS – on käytössä pilottiin osallistuneiden oppilaitosten digitaalisissa oppimistuotteissa ja osassa näistä oppimistuotteista on toteutettu kirjautumistapa, joka perustuu muuhun kuin käyttäjätunnus / salasana –yhdistelmään. 
Sen lisäksi palveluntarjoajille ja oppilaitoksille tuotettu SDK on valmis.

##2.3. Projektin kuvaus ja kohde
Suomen koulutusjärjestelmään kuuluvissa perus- ja toisen asteen oppilaitoksissa on käytössä laaja kirjo erilaisia järjestelmiä ja ohjelmistoja, jotka vaativat käyttäjältään kirjautumista. Käytännössä on muodostunut tilanne, jossa yksittäinen käyttäjä joutuu ylläpitämään useita erilaisia tunnuksia ja salasanoja.  Tilanne aiheuttaa perus- ja toisen asteen oppilaitoksissa ajallista resurssihukkaa, joka on pois opetukseen käytettävästä ajasta. Ongelma koskettaa noin 900 000 oppilasta sekä 100 000 henkilökuntaan laskettavaa henkilöä, jotka ovat jakautuneet useisiin satoihin kuntiin ja niissä edelleen tuhansiin oppilaitoksiin. Tilanteen ratkaisu toisi merkittävää parannusta digitaalisten oppimistuotteiden käyttökokemukseen sekä parantaisi resurssitehokkuutta oppilaitoksissa, joissa hyödynnetään digitaalisia oppimisjärjestelmiä tai oppimismateriaaleja. Yliopistoilla ja ammattikorkeakouluilla tilanne on ratkaistu jo pidemmän aikaa HAKA-luottamusverkostolla ja identiteettihallintakäytännöllä, jolloin yksittäisellä opiskelijalla on käytössään yksi käyttäjätunnus ja salasana, joka on käytössä kaikissa eri järjestelmissä. Viranomaisten järjestelmissä vastaava ratkaisu on ollut Virtu-tunnistautumisjärjestelmä.
Koska perus- ja toisen asteen oppilaitosten opiskelijoista suurin osa on alaikäisiä, tulee tunnistautumisratkaisu hyödyntää kevyitä tunnistautumisratkaisuja nykyisten vahvojen tunnistautumiskäytäntöjen sijaan. Olemassa olevat vahvan tunnistautumisen käytännöt ovat toimivuudeltaan jäykkiä. Tämän lisäksi alle 15-vuotiden osalta Vetuma-tunnistautuminen pohjautuu pitkälti verkkopankkitunnuksiin, joita ei myönnetä alle 15-vuotiailla ja vain osalla 15-17 –vuotiaista on niitä käytössä. Toisen haasteen tunnistautumisratkaisulle asettavat ne lapset, jotka ovat oppilaitoksissa mutta eivät ole vielä oppineet lukemaan. Näissä tapauksissa kirjautumis- ja tunnistautumisratkaisun tulisi olla sellainen, joka ei pohjaudu käyttäjätunnus ja salasana –yhdistelmään. Tulee lisäksi ottaa huomioon liikehdintä, jossa muutenkin pyritään kehittämään edistyneempiä tunnistautumisratkaisuja henkilökohtaisten digitaalisten palveluiden käyttöön. 

##2.4. Ratkottavat ongelmat ja tavoitteet

*Keskeiset ratkottavat ongelmat ovat:*
- SDK:n tuottaminen siten että se vastaa oppilaitosten ja palvelun tarjoajien tarpeeseen
- IdP-lähteiden hallinta pilotin ensimmäisen vaiheen aikana. 
- Kirjoitustaidottomille suunnattujen kirjautumiskäytäntöjen kartoitus ja kokeilu
- OID:n IdP-käyttöön liittyvien esteiden tai haasteiden kartoitus
*Projektin keskeisimmät tavoitteet ovat:*
- MPASS-kirjautumisratkaisun jalkauttaminen mahdollisimman laajalle
 - MPASS-kirjautumisratkaisun helpon käyttöönoton ratkaisu
- Pilottikoulujen IdP-lähteiden hallinta*
    ...
##2.5. Projektin omistaja.
    Tuotepäällikkö:  (OKM)
    Projektipäällikkö: nimetään myöhemmin, vastaa läpiviennistä.

##2.7. Toteutuksen osapuolet
    OKM/kopo
    Asiakasedustaja: EduCloud Alliance
    Asiakasedustaja: Koulu x
    Asiakasedustaja: Koulu y
    Asiakasedustaja: Yritys/yhdistys z
    Toteuttava osapuoli: CSC
#3. Toteutus

##3.1. Läpiviennin yleiset periaatteet
    Miten kytkeytyy isoon kuvaan OKM ja valtion tasolla?
    - Lainmuutoksia vaativat asiat, Seuraavassa vaiheessa yhteys OID:n teknisellä tasolla
    Miten varmistetaan tiedonkulku muiden hankkeiden suuntaan?
    Yhteistyön kuvaaminen, miten siilot rikotaan?

##3.2. Aikataulu ja vaiheistus
Kehitysprojektin tämä vaihe toteutetaan 10/2015 - 12/2015. Keväällä 2016 jatkokehitys.

##3.3. Vaiheet
Alla on kuvattu projektiin sisältyvien osaprojektien/tehtäväkokonaisuuksien päävaiheet ja niiden keskeiset tehtävät.

###3.3.1. MPASS Kirjautumisjärjestelmä 
Valmis

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

###3.3.4. MPASS SDK
Vaihe tehdään 14.8.- 31.09.2015 välisenä aikana.
Vaiheessa syntyvät tuotokset:

###3.3.5 Evaluointi ja jatkosta päättäminen
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

